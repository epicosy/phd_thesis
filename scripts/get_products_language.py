import sqlite3
import pandas as pd

from tqdm import tqdm
from os import environ
from typing import List
from pathlib import Path

from gitlib import GitClient
from gitlib.common.exceptions import GitLibException
from cpeparser import CpeParser
from packageurl import PackageURL

cpe_parser = CpeParser()

GITHUB_TOKEN = environ.get("GITHUB_TOKEN")
git_client = GitClient(GITHUB_TOKEN)

if not GITHUB_TOKEN:
    raise ValueError("GITHUB_TOKEN environment variable not set")

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


def load_purl2cpe_pairs(db_file) -> List[tuple]:
    """
    Connects to the SQLite database and retrieves all (purl, cpe) pairs.
    :param db_file: Path to the SQLite database file
    :return: List of (purl, cpe) tuples
    """
    if not db_file:
        raise ValueError("No database file specified.")

    conn = sqlite3.connect(db_file)
    cursor = conn.cursor()
    _pairs = []

    try:
        cursor.execute("SELECT purl, cpe FROM purl2cpe;")
        _pairs = cursor.fetchall()
    finally:
        conn.close()

    return _pairs


def get_vendor_product_purl_df(purl_cpe_pairs: List[tuple]) -> pd.DataFrame:
    rows = []

    for purl, cpe in tqdm(purl_cpe_pairs):
        cpe_obj = cpe_parser.parser(cpe)

        try:
            purl_obj = PackageURL.from_string(purl)
        except ValueError as e:
            # print(f"Error parsing purl: {purl}")
            continue

        row = purl_obj.to_dict()
        row.update({"vendor": cpe_obj['vendor'], "product": cpe_obj['product']})
        rows.append(row)

    mappings_df = pd.DataFrame(rows)
    mappings_df.drop_duplicates(subset=["vendor", "product"], inplace=True)
    print(f"Found {len(mappings_df)} vendor-product-repo mappings")

    return mappings_df


def map_pkg_to_language(purl_cpe_df: pd.DataFrame) -> pd.DataFrame:
    new_rows = []

    for group, rows in purl_cpe_df.groupby(["vendor", "product"]):
        purl_types = set(rows['type'].unique())
        intersection = purl_types.intersection(list(PURL_TYPE_LANGUAGE_MAPPING.keys()))
        selected_type = None
        row = None
        language = None

        if 'github' in purl_types:
            row = rows[rows['type'] == 'github'].iloc[0].to_dict()
            selected_type = 'github'

        if len(intersection) == 0:
            if not row:
                continue
        elif len(intersection) == 1:
            selected_type = intersection.pop()
            language = PURL_TYPE_LANGUAGE_MAPPING[selected_type]
        else:
            print(f"Found multiple purl types for {group}: {list(intersection)}")

        if not selected_type:
            continue

        if not row:
            row = rows[rows['type'] == selected_type].iloc[0].to_dict()

        row['language'] = language
        new_rows.append(row)

    return pd.DataFrame(new_rows)


def get_products_language_df(products_df_path: Path, purl_db_path: Path) -> pd.DataFrame:
    data_df = pd.read_csv(products_df_path)
    products = data_df["product"].unique()

    print(f"Found {len(products)} products in the dataset")

    pairs = load_purl2cpe_pairs(purl_db_path)
    product_purl_df = get_vendor_product_purl_df(pairs)
    print(product_purl_df.head())

    product_purl_df = product_purl_df[product_purl_df["product"].isin(products)]
    print(f"Found {len(product_purl_df)} products with purl mappings")

    _pro_lang_df = map_pkg_to_language(product_purl_df)
    print(f"Found {len(_pro_lang_df)} products with language/repository mappings")
    print(_pro_lang_df['language'].value_counts())

    _pro_lang_df.to_csv(rq1_data_path / "products_language.csv", index=False)

    return _pro_lang_df


def get_products_language_from_repository(prod_lang_df: pd.DataFrame, output_path: Path) -> pd.DataFrame:
    for i, row in tqdm(prod_lang_df.iterrows(), total=len(prod_lang_df)):
        if not pd.isna(row['language']):
            continue

        if row['language'] == 'N/A':
            continue

        if row['type'] == 'github':
            try:
                repo = git_client.get_repo(owner=row['namespace'], project=row['name'], raise_err=True)
                language = repo.language
                prod_lang_df.loc[i, 'language'] = language if language else 'N/A'
            except GitLibException as gle:
                if 'limit exhausted' not in str(gle):
                    print(gle)
                    prod_lang_df.loc[i, 'language'] = 'N/A'
                    continue
                else:
                    break

    prod_lang_df.to_csv(output_path, index=False)

    return prod_lang_df


root_path = Path(__file__).parent.parent
rq1_data_path = root_path / "data" / "rq1"
output_file_path = rq1_data_path / "products_language.csv"

if output_file_path.exists():
    product_language_df = pd.read_csv(output_file_path)
else:
    product_language_df = get_products_language_df(
        products_df_path=rq1_data_path / "cve_ids_in_apps_with_cwe.csv",
        purl_db_path=Path("~/projects/purl2cpe.db").expanduser()
    )

product_language_df = get_products_language_from_repository(product_language_df, output_file_path)
print(product_language_df['language'].value_counts())
