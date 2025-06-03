import sqlite3
import pandas as pd
import logging
import sys

from tqdm import tqdm
from os import environ
from typing import List, Dict, Set, Optional, Tuple
from pathlib import Path

from gitlib import GitClient
from gitlib.common.exceptions import GitLibException
from cpeparser import CpeParser
from packageurl import PackageURL

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[logging.StreamHandler(sys.stdout)]
)
logger = logging.getLogger(__name__)

# Constants
PURL_TYPE_LANGUAGE_MAPPING = {
    "maven": "Java",
    "pypi": "Python",
    "npm": "JavaScript",
    "gem": "Ruby",
    "composer": "PHP",
    "nuget": "C#",
    "cpan": "Perl",
    "gnu": "C",
    "wordpress": "PHP",
    "cargo": "Rust",
    "drupal": "PHP",
    "eclipse": "Java"
}


def initialize_clients():
    """
    Initialize the CPE parser and Git client.

    Returns:
        Tuple[CpeParser, GitClient]: Initialized CPE parser and Git client

    Raises:
        ValueError: If GITHUB_TOKEN environment variable is not set
    """
    cpe_parser = CpeParser()

    github_token = environ.get("GITHUB_TOKEN")
    if not github_token:
        raise ValueError("GITHUB_TOKEN environment variable not set")

    git_client = GitClient(github_token)

    return cpe_parser, git_client


def load_purl2cpe_pairs(db_file: Path) -> List[tuple]:
    """
    Connects to the SQLite database and retrieves all (purl, cpe) pairs.

    Args:
        db_file: Path to the SQLite database file

    Returns:
        List of (purl, cpe) tuples

    Raises:
        ValueError: If no database file is specified
    """
    if not db_file:
        raise ValueError("No database file specified.")

    conn = sqlite3.connect(db_file)
    cursor = conn.cursor()
    _pairs = []

    try:
        cursor.execute("SELECT purl, cpe FROM purl2cpe;")
        _pairs = cursor.fetchall()
        logger.info(f"Loaded {len(_pairs)} purl-cpe pairs from database")
    except sqlite3.Error as e:
        logger.error(f"Database error: {e}")
        raise
    finally:
        conn.close()

    return _pairs


def get_vendor_product_purl_df(purl_cpe_pairs: List[tuple], cpe_parser: CpeParser) -> pd.DataFrame:
    """
    Create a DataFrame with vendor-product-purl mappings from purl-cpe pairs.

    Args:
        purl_cpe_pairs: List of (purl, cpe) tuples
        cpe_parser: Initialized CPE parser

    Returns:
        DataFrame with vendor-product-purl mappings
    """
    rows = []

    for purl, cpe in tqdm(purl_cpe_pairs, desc="Processing purl-cpe pairs"):
        try:
            cpe_obj = cpe_parser.parser(cpe)
        except Exception as e:
            logger.warning(f"Error parsing CPE: {cpe}, Error: {e}")
            continue

        try:
            purl_obj = PackageURL.from_string(purl)
        except ValueError as e:
            logger.debug(f"Error parsing purl: {purl}, Error: {e}")
            continue

        row = purl_obj.to_dict()
        row.update({"vendor": cpe_obj['vendor'], "product": cpe_obj['product']})
        rows.append(row)

    mappings_df = pd.DataFrame(rows)
    mappings_df.drop_duplicates(subset=["vendor", "product"], inplace=True)
    logger.info(f"Found {len(mappings_df)} vendor-product-repo mappings")

    return mappings_df


def determine_language_from_purl_type(purl_types: Set[str]) -> Tuple[Optional[str], Optional[str]]:
    """
    Determine the programming language based on package URL types.

    Args:
        purl_types: Set of package URL types

    Returns:
        Tuple of (selected_type, language)
    """
    intersection = purl_types.intersection(list(PURL_TYPE_LANGUAGE_MAPPING.keys()))
    selected_type = None
    language = None

    # Determine language based on package type
    if len(intersection) == 1:
        selected_type = intersection.pop()
        language = PURL_TYPE_LANGUAGE_MAPPING[selected_type]
    elif len(intersection) > 1:
        logger.info(f"Found multiple purl types: {list(intersection)}")

    return selected_type, language


def select_row_for_product(rows: pd.DataFrame, purl_types: Set[str], selected_type: Optional[str]) -> Optional[dict]:
    """
    Select the most appropriate row for a product based on package type.

    Args:
        rows: DataFrame rows for a specific vendor-product pair
        purl_types: Set of package URL types
        selected_type: Selected package type for language determination

    Returns:
        Selected row as a dictionary or None if no suitable row found
    """
    # Prefer GitHub repositories
    if 'github' in purl_types:
        return rows[rows['type'] == 'github'].iloc[0].to_dict()

    # If we have a selected type, use that
    if selected_type:
        return rows[rows['type'] == selected_type].iloc[0].to_dict()

    return None


def map_pkg_to_language(purl_cpe_df: pd.DataFrame) -> pd.DataFrame:
    """
    Map packages to programming languages using package type information.

    Args:
        purl_cpe_df: DataFrame with vendor-product-purl mappings

    Returns:
        DataFrame with vendor-product-language mappings
    """
    new_rows = []

    for group, rows in tqdm(purl_cpe_df.groupby(["vendor", "product"]), 
                           desc="Mapping packages to languages", 
                           total=len(purl_cpe_df.groupby(["vendor", "product"]))):
        purl_types = set(rows['type'].unique())

        # Determine language based on package type
        selected_type, language = determine_language_from_purl_type(purl_types)

        # Select the most appropriate row
        row = select_row_for_product(rows, purl_types, selected_type)

        # Skip if no suitable row found
        if not row:
            continue

        row['language'] = language
        new_rows.append(row)

    result_df = pd.DataFrame(new_rows)
    logger.info(f"Mapped {len(result_df)} products to languages")

    return result_df


def get_products_language_df(purl_db_path: Path, output_path: Path, cpe_parser: CpeParser) -> pd.DataFrame:
    """
    Get a DataFrame with product-language mappings from the purl2cpe database.

    Args:
        purl_db_path: Path to the purl2cpe database
        output_path: Path to save the output CSV file
        cpe_parser: Initialized CPE parser

    Returns:
        DataFrame with product-language mappings
    """
    pairs = load_purl2cpe_pairs(purl_db_path)
    product_purl_df = get_vendor_product_purl_df(pairs, cpe_parser)

    if logger.isEnabledFor(logging.DEBUG):
        logger.debug(f"Sample of product-purl mappings:\n{product_purl_df.head()}")

    logger.info(f"Found {len(product_purl_df)} products with purl mappings")

    product_lang_df = map_pkg_to_language(product_purl_df)
    logger.info(f"Found {len(product_lang_df)} products with language/repository mappings")
    logger.info(f"Language distribution:\n{product_lang_df['language'].value_counts()}")

    # Save to CSV
    product_lang_df.to_csv(output_path, index=False)
    logger.info(f"Saved product-language mappings to {output_path}")

    return product_lang_df


def query_github_repository_language(
    git_client: GitClient, 
    namespace: str, 
    name: str
) -> Optional[str]:
    """
    Query GitHub API for repository language information.

    Args:
        git_client: Initialized Git client
        namespace: Repository owner/namespace
        name: Repository name

    Returns:
        Repository language or None if not available
    """
    try:
        repo = git_client.get_repo(owner=namespace, project=name, raise_err=True)
        language = repo.language
        logger.debug(f"Retrieved language for {namespace}/{name}: {language}")
        return language if language else 'N/A'
    except GitLibException as gle:
        if 'limit exhausted' in str(gle):
            logger.warning("GitHub API rate limit exhausted. Stopping queries.")
            raise
        else:
            logger.warning(f"Error querying GitHub repository: {namespace}/{name}, Error: {gle}")
            return 'N/A'


def update_language_for_row(
    prod_lang_df: pd.DataFrame, 
    index: int, 
    row: pd.Series, 
    git_client: GitClient
) -> bool:
    """
    Update language information for a single row in the DataFrame.

    Args:
        prod_lang_df: DataFrame with product-language mappings
        index: Row index in the DataFrame
        row: Row data as a Series
        git_client: Initialized Git client

    Returns:
        True if API rate limit was reached, False otherwise
    """
    # Skip if language is already known
    if not pd.isna(row['language']) and row['language'] != 'N/A':
        return False

    # Only process GitHub repositories
    if row['type'] == 'github':
        try:
            language = query_github_repository_language(git_client, row['namespace'], row['name'])
            prod_lang_df.loc[index, 'language'] = language
        except GitLibException:
            # Rate limit reached
            return True

    return False


def get_products_language_from_repository(
    prod_lang_df: pd.DataFrame, 
    output_path: Path, 
    git_client: GitClient
) -> pd.DataFrame:
    """
    Update language information for products by querying GitHub repositories.

    Args:
        prod_lang_df: DataFrame with product-language mappings
        output_path: Path to save the updated CSV file
        git_client: Initialized Git client

    Returns:
        Updated DataFrame with product-language mappings
    """
    missing_language_count = len(prod_lang_df[pd.isna(prod_lang_df['language'])])
    logger.info(f"Updating language information for {missing_language_count} products from GitHub repositories")

    for i, row in tqdm(prod_lang_df.iterrows(), total=len(prod_lang_df), desc="Querying GitHub repositories"):
        rate_limit_reached = update_language_for_row(prod_lang_df, i, row, git_client)
        if rate_limit_reached:
            break

    # Save updated DataFrame to CSV
    save_and_log_results(prod_lang_df, output_path)

    return prod_lang_df


def save_and_log_results(prod_lang_df: pd.DataFrame, output_path: Path) -> None:
    """
    Save DataFrame to CSV and log results.

    Args:
        prod_lang_df: DataFrame with product-language mappings
        output_path: Path to save the CSV file
    """
    prod_lang_df.to_csv(output_path, index=False)
    logger.info(f"Saved updated product-language mappings to {output_path}")

    updated_count = len(prod_lang_df) - len(prod_lang_df[pd.isna(prod_lang_df['language'])])
    logger.info(f"Updated language information for {updated_count} out of {len(prod_lang_df)} products")


def load_existing_data(output_path: Path) -> pd.DataFrame:
    """
    Load existing product-language mappings from CSV file.

    Args:
        output_path: Path to the existing CSV file

    Returns:
        DataFrame with existing product-language mappings
    """
    logger.info(f"Loading existing data from {output_path}")
    return pd.read_csv(output_path)


def find_new_products(
    product_purl_df: pd.DataFrame, 
    existing_pairs: Set[Tuple[str, str]]
) -> List[dict]:
    """
    Find products in the database that are not in the existing data.

    Args:
        product_purl_df: DataFrame with all products from the database
        existing_pairs: Set of existing (vendor, product) pairs

    Returns:
        List of new product rows
    """
    new_products = []
    for _, row in tqdm(product_purl_df.iterrows(), desc="Finding new products", total=len(product_purl_df)):
        if (row['vendor'], row['product']) not in existing_pairs:
            new_products.append(row)

    if new_products:
        logger.info(f"Found {len(new_products)} new products not in the existing data")
    else:
        logger.info("No new products found in the database")

    return new_products


def process_new_products(
    new_products: List[dict], 
    existing_df: pd.DataFrame
) -> pd.DataFrame:
    """
    Process new products and merge them with existing data.

    Args:
        new_products: List of new product rows
        existing_df: DataFrame with existing product-language mappings

    Returns:
        Updated DataFrame with product-language mappings
    """
    if not new_products:
        return existing_df

    new_products_df = pd.DataFrame(new_products)

    # Process only the new products
    new_lang_df = map_pkg_to_language(new_products_df)
    logger.info(f"Processed {len(new_lang_df)} new products with language mappings")

    # Merge with existing data
    product_language_df = pd.concat([existing_df, new_lang_df], ignore_index=True)
    logger.info(f"Total products after merging: {len(product_language_df)}")

    return product_language_df


def process_existing_data(
    output_path: Path, 
    purl_db_path: Path, 
    cpe_parser: CpeParser
) -> pd.DataFrame:
    """
    Process existing data and update it with new products from the database.

    Args:
        output_path: Path to the existing CSV file
        purl_db_path: Path to the purl2cpe database
        cpe_parser: Initialized CPE parser

    Returns:
        Updated DataFrame with product-language mappings
    """
    # Load existing data
    existing_df = load_existing_data(output_path)

    # Load all products from the database
    logger.info(f"Loading products from database to find new entries...")
    pairs = load_purl2cpe_pairs(purl_db_path)
    product_purl_df = get_vendor_product_purl_df(pairs, cpe_parser)

    # Create a set of existing vendor-product pairs for quick lookup
    existing_pairs = set(zip(existing_df['vendor'], existing_df['product']))

    # Find new products
    new_products = find_new_products(product_purl_df, existing_pairs)

    # Process new products and merge with existing data
    return process_new_products(new_products, existing_df)


def count_and_log_languages(product_language_df: pd.DataFrame) -> pd.Series:
    """
    Count languages based on unique repositories for GitHub entries and product for non-GitHub entries.
    Keeps only the top 20 languages and groups the rest under "Others".

    Args:
        product_language_df: DataFrame with product-language mappings

    Returns:
        Series with language counts (top 20 + Others)
    """
    # Split DataFrame into GitHub repositories and non-GitHub entries
    github_repos = product_language_df[product_language_df['type'] == 'github'].copy()
    non_github = product_language_df[product_language_df['type'] != 'github'].copy()

    # Count languages for GitHub repositories based on unique repositories
    if not github_repos.empty:
        github_repos['repo_id'] = github_repos['namespace'] + '/' + github_repos['name']
        # Drop duplicates to count each repository only once
        unique_repos = github_repos.drop_duplicates(subset=['repo_id'])
        logger.info(f"Found {len(unique_repos)} unique repositories in GitHub entries")
        github_lang_counts = unique_repos['language'].value_counts()
    else:
        github_lang_counts = pd.Series(dtype='int64')

    # Count languages for non-GitHub entries
    if not non_github.empty:
        logger.info(f"Found {len(non_github)} non-GitHub entries")
        non_github_lang_counts = non_github['language'].value_counts()
    else:
        non_github_lang_counts = pd.Series(dtype='int64')

    # Combine the counts
    combined_counts = github_lang_counts.add(non_github_lang_counts, fill_value=0).astype(int)

    # Keep only the top 20 languages and group the rest under "Others"
    if len(combined_counts) > 20:
        top_20_languages = combined_counts.nlargest(20)
        # Get the sum of all languages that are not in the top 20
        others_count = combined_counts.sum() - top_20_languages.sum()

        # Create a new Series with top 20 + Others
        result_counts = top_20_languages.copy()
        if others_count > 0:
            result_counts['Others'] = others_count
    else:
        result_counts = combined_counts

    logger.info(f"Final language distribution (top 20 + Others, counting unique repositories):\n{result_counts}")

    return result_counts


def initialize_paths(purl_db_path: Optional[Path] = None, output_dir: Optional[Path] = None) -> Tuple[Path, Path]:
    """
    Initialize paths for the database and output directory.

    Args:
        purl_db_path: Path to the purl2cpe database (default: ~/projects/purl2cpe.db)
        output_dir: Directory to save the output CSV file (default: <repo_root>/data/rq1)

    Returns:
        Tuple of (purl_db_path, output_file_path)
    """
    # Initialize database path
    if purl_db_path is None:
        purl_db_path = Path("~/projects/purl2cpe.db").expanduser()

    # Initialize output directory
    if output_dir is None:
        root_path = Path(__file__).parent.parent
        output_dir = root_path / "data" / "rq1"

    # Ensure output directory exists
    output_dir.mkdir(parents=True, exist_ok=True)

    # Create output file path
    output_file_path = output_dir / "products_language.csv"

    return purl_db_path, output_file_path


def process_data(purl_db_path: Path, output_file_path: Path, cpe_parser: CpeParser, git_client: GitClient) -> pd.DataFrame:
    """
    Process data to create or update product-language mappings.

    Args:
        purl_db_path: Path to the purl2cpe database
        output_file_path: Path to save the output CSV file
        cpe_parser: Initialized CPE parser
        git_client: Initialized Git client

    Returns:
        DataFrame with product-language mappings
    """
    # Process data based on whether existing data exists
    if output_file_path.exists():
        product_language_df = process_existing_data(output_file_path, purl_db_path, cpe_parser)
    else:
        logger.info(f"No existing data found. Running full analysis...")
        product_language_df = get_products_language_df(purl_db_path, output_file_path, cpe_parser)

    # Always try to update language information for entries that don't have it yet
    product_language_df = get_products_language_from_repository(
        product_language_df,
        output_file_path,
        git_client
    )

    return product_language_df


def main(purl_db_path: Optional[Path] = None, output_dir: Optional[Path] = None):
    """
    Main function to run the product language mapping process.

    Args:
        purl_db_path: Path to the purl2cpe database (default: ~/projects/purl2cpe.db)
        output_dir: Directory to save the output CSV file (default: <repo_root>/data/rq1)

    Returns:
        DataFrame with product-language mappings
    """
    # Initialize paths
    purl_db_path, output_file_path = initialize_paths(purl_db_path, output_dir)

    # Initialize clients
    cpe_parser, git_client = initialize_clients()

    # Process data
    product_language_df = process_data(purl_db_path, output_file_path, cpe_parser, git_client)

    # Count languages and log results
    count_and_log_languages(product_language_df)
    logger.info(f"Process completed successfully. Results saved to {output_file_path}")

    return product_language_df


if __name__ == "__main__":
    main()
