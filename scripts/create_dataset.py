import re
import pandas as pd

from tqdm import tqdm
from typing import List
from pathlib import Path
from typing import Optional

from cpelib.types.definitions import CPEPart

from nvdutils.loaders.json.default import JSONDefaultLoader
from nvdutils.models.configurations import Configurations


root_path = Path(__file__).parent.parent
data_path = root_path / "data" / "rq1"
output_file_path = data_path / "dataset.csv"


SOFTWARE_TYPE_SCORE = {
    "utility": 1,
    "framework": 1,
    "server": 1,
    "web_app": 2,
    "mobile_app": 2,
    "library": 3,
    "extension": 3,
}


# Mapping of file extensions to programming languages
FILE_EXTENSION_TO_LANGUAGE = {
    # Web/Scripting
    "js": "JavaScript",
    "ts": "TypeScript",
    "jsx": "JavaScript",
    "tsx": "TypeScript",
    "php": "PHP",
    "py": "Python",
    "rb": "Ruby",
    "pl": "Perl",
    "sh": "Shell",
    "bash": "Shell",
    "zsh": "Shell",
    "html": "HTML",
    "htm": "HTML",
    "css": "CSS",
    "scss": "CSS",
    "less": "CSS",

    # Compiled languages
    "c": "C",
    "h": "C",
    "cpp": "C++",
    "cc": "C++",
    "cxx": "C++",
    "hpp": "C++",
    "hxx": "C++",
    "java": "Java",
    "cs": "C#",
    "go": "Go",
    "rs": "Rust",
    "swift": "Swift",
    "kt": "Kotlin",
    "scala": "Scala",

    # Data/Config
    "json": "JSON",
    "xml": "XML",
    "yaml": "YAML",
    "yml": "YAML",
    "toml": "TOML",
    "sql": "SQL",

    # Other
    "md": "Markdown",
    "rst": "reStructuredText"
}


def get_product_details_df(product_lang_df_path: Path, product_sw_type_df_path: Path) -> dict:
    product_lang_df = pd.read_csv(product_lang_df_path)
    product_sw_type_df = pd.read_csv(product_sw_type_df_path)
    product_details = {}

    merged_df = pd.merge(product_lang_df, product_sw_type_df, on=["vendor", "product"], how="inner")
    merged_df.rename(columns={"type": "package_type"}, inplace=True)
    merged_df.dropna(subset=["language", "software_type"], inplace=True)
    print(f"Found {len(merged_df)} products with language and software type")

    for _, row in tqdm(merged_df.iterrows(), total=len(merged_df), desc="Loading products details."):
        row_dict = row[['vendor', 'product', 'package_type', 'software_type', 'language']].to_dict()
        product_details[f"{row['vendor']}_{row['product']}"] = row_dict

    return product_details


def select_vulnerable_product(configurations: Configurations, products_details: dict) -> Optional[dict]:
    best_product = (None, -1)

    for vuln_prod in configurations.vulnerable_products:
        if vuln_prod.part != CPEPart.Application:
            continue

        product_id = f"{vuln_prod.vendor}_{vuln_prod.name}"

        if product_id not in products_details:
            continue

        product_dict = products_details[product_id]
        product_score = SOFTWARE_TYPE_SCORE[product_dict['software_type']]
        product_score += 1 if product_dict['package_type'] == 'github' else 0

        if product_score > best_product[1]:
            best_product = (product_dict, product_score)

    return best_product[0]


def extract_file_names(description: str) -> List[str]:
    """
    Extract potential file names from a description text.

    Args:
        description: The CVE description text

    Returns:
        A list of potential file names found in the description
    """
    # Match file-like strings, with at least one letter before the dot
    # and a known file extension (to reduce false positives)
    file_extensions = list(FILE_EXTENSION_TO_LANGUAGE.keys())

    # Join extensions into a regex group
    ext_group = '|'.join(file_extensions)

    # Regex: match strings like `index.php`, not `1.2.3`
    file_name_pattern = rf'\b[a-zA-Z0-9_\-/]+\.({ext_group})\b'

    # Find all matches
    file_names = re.findall(file_name_pattern, description)

    return file_names


def determine_language_from_file_paths(file_paths: List[str]) -> Optional[str]:
    """
    Determine the most likely programming language based on file extensions.

    Args:
        file_paths: List of file paths extracted from the description

    Returns:
        The most likely programming language or None if no match found
    """
    if not file_paths:
        return None

    # Count occurrences of each language
    language_counts = {}

    for path in file_paths:
        # Extract extension
        extension = path.split('.')[-1].lower()

        # Check if extension is in our mapping
        if extension in FILE_EXTENSION_TO_LANGUAGE:
            language = FILE_EXTENSION_TO_LANGUAGE[extension]
            language_counts[language] = language_counts.get(language, 0) + 1

    # Return the most common language if any were found
    if language_counts:
        return max(language_counts.items(), key=lambda x: x[1])[0]

    return None


def create_dataset_df(nvd_data_path: Path, cve_cwe_df: pd.DataFrame, product_details: dict) -> pd.DataFrame:
    rows = []
    loader = JSONDefaultLoader()
    index = {file.stem: file for file in nvd_data_path.expanduser().rglob(r"CVE*.json")}
    print(f"Found {len(index)} CVE files")
    language_from_description_count = 0

    for i, row in tqdm(cve_cwe_df.iterrows()):
        cve = loader.load_by_id(cve_id=row.cve_id, index=index)

        vulnerable_product = select_vulnerable_product(
            configurations=cve.configurations, products_details=product_details
        )

        if not vulnerable_product:
            continue

        row_dict = row.to_dict()
        row_dict.update(vulnerable_product)

        # Try to extract language from description if available
        file_names = extract_file_names(cve.descriptions.get_eng_description().value)
        language_from_description = determine_language_from_file_paths(file_names)

        # Update language if found in description
        if language_from_description:
            row_dict['language'] = language_from_description
            row_dict['language_source'] = 'description'
            language_from_description_count += 1
        else:
            row_dict['language_source'] = 'product_details'

        rows.append(row_dict)

    _df = pd.DataFrame(rows)
    print(f"Found {len(_df)} CVEs with product details.")
    print(f"Found {language_from_description_count} CVEs with language determined from description")

    return _df


if output_file_path.exists():
    df = pd.read_csv(output_file_path)
else:
    _product_details = get_product_details_df(
        product_lang_df_path=data_path / "products_language.csv", product_sw_type_df_path=data_path / "software_type.csv"
    )
    _cve_cwe_df = pd.read_csv(data_path / "cve_ids_in_apps_with_cwe.csv")

    df = create_dataset_df(
        nvd_data_path=Path("~/.nvdutils/nvd-json-data-feeds"), cve_cwe_df=_cve_cwe_df, product_details=_product_details
    )

    df.to_csv(output_file_path, index=False)

counts = df[["software_type", "language", "cwe_id"]].value_counts()
top_25_counts = counts.head(25)

print(f"Top 25 Relationship Counts:\n{top_25_counts}")
