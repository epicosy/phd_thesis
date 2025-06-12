import re
import json
import pandas as pd

from tqdm import tqdm
from typing import List
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse

from cpelib.types.definitions import CPEPart

from nvdutils.models.configurations import Configurations
from nvdutils.loaders.json.default import JSONDefaultLoader


root_path = Path(__file__).parent.parent
data_path = root_path / "data" / "rq1"
output_file_path = data_path / "dataset.csv"
language_extension_mapping_file_path = data_path / "language_extension_mapping.json"


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
LANGUAGE_EXTENSION_MAPPING = json.load(open(language_extension_mapping_file_path))
LANGUAGE_FILE_EXTENSIONS = list(set([_ext[1:].lower() for _langs in LANGUAGE_EXTENSION_MAPPING.values() for _exts in _langs.values() for _ext in _exts]))

# Match file-like strings, with at least one letter before the dot
# and a known file extension (to reduce false positives)
# Join extensions into a regex group
EXT_GROUP = '|'.join(LANGUAGE_FILE_EXTENSIONS)

# Regex: match strings like `index.php`, not `1.2.3`
FILE_NAME_PATTERN = rf'\b[a-zA-Z0-9_\-/]+\.({EXT_GROUP})\b'
# A rough pattern to detect if a match is part of a URL
URL_PATTERN = re.compile(r'https?://[^\s]+')


def get_product_details_df(product_lang_df_path: Path, product_sw_type_df_path: Path) -> dict:
    product_lang_df = pd.read_csv(product_lang_df_path)
    product_sw_type_df = pd.read_csv(product_sw_type_df_path)
    product_details = {}

    merged_df = pd.merge(product_lang_df, product_sw_type_df, on=["vendor", "product"], how="outer")
    merged_df.rename(columns={"type": "package_type"}, inplace=True)
    merged_df = merged_df.applymap(lambda x: None if pd.isna(x) else x)

    # merged_df.dropna(subset=["language", "software_type"], inplace=True)
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
        product_score = 0

        if product_dict['software_type']:
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
    # Find all matches
    urls = re.findall(URL_PATTERN, description)

    for url in urls:
        # remove the hostname so it does not pick the top-level domain
        description = description.replace(urlparse(url).hostname, '')

    file_names = re.findall(FILE_NAME_PATTERN, description)

    return file_names


def determine_language_from_file_names(file_paths: List[str]) -> Optional[str]:
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
        for category, languages in LANGUAGE_EXTENSION_MAPPING.items():
            for language, extensions in languages.items():
                if f".{extension}" in extensions:
                    language_counts[language] = language_counts.get(language, 0) + 1
                    break

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
        language_from_description = determine_language_from_file_names(file_names)

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
