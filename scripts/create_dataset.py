import pandas as pd

from tqdm import tqdm
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


def create_dataset_df(nvd_data_path: Path, cve_cwe_df: pd.DataFrame, product_details: dict) -> pd.DataFrame:
    rows = []
    loader = JSONDefaultLoader()
    index = {file.stem: file for file in nvd_data_path.expanduser().rglob(r"CVE*.json")}
    print(f"Found {len(index)} CVE files")

    for i, row in tqdm(cve_cwe_df.iterrows()):
        cve = loader.load_by_id(cve_id=row.cve_id, index=index)

        vulnerable_product = select_vulnerable_product(
            configurations=cve.configurations, products_details=product_details
        )

        if not vulnerable_product:
            continue

        row_dict = row.to_dict()
        row_dict.update(vulnerable_product)
        rows.append(row_dict)

    _df = pd.DataFrame(rows)
    print(f"Found {len(_df)} CVEs with CWEs")
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

    df.to_csv(output_file_path)

counts = df[["software_type", "language", "cwe_id"]].value_counts()
top_25_counts = counts.head(25)

print(f"Top 25 Relationship Counts:\n{top_25_counts}")
