import pandas as pd

from tqdm import tqdm
from pathlib import Path
from typing import Optional
from dataclasses import dataclass, field

from cpelib.types.definitions import CPEPart

from nvdutils.common.enums.weaknesses import WeaknessType
from nvdutils.loaders.json.default import JSONDefaultLoader

from nvdutils.models.cve import CVE
from nvdutils.models.weaknesses import Weaknesses
from nvdutils.models.configurations import Configurations

from nvdutils.data.criteria.cve import CVECriteria
from nvdutils.data.profiles.base import BaseProfile
from nvdutils.data.criteria.weaknesses import CWECriteria, WeaknessesCriteria
from nvdutils.data.criteria.configurations import AffectedProductCriteria, ConfigurationsCriteria


root_path = Path(__file__).parent.parent
data_path = root_path / "data"
output_file_path = data_path / "rq1" / "cve_ids_in_apps_with_cwe.csv"

weakness_criteria = WeaknessesCriteria(
    cwe_criteria=CWECriteria(),
    weakness_type=WeaknessType.Primary
)

app_config_criteria = ConfigurationsCriteria(
    affected_products=AffectedProductCriteria(
        part=CPEPart.Application
    )
)


CWE_ABSTRACTION_SCORE = {
    "Chain": 0,
    "Composite": 1,
    "Class": 2,
    "Base": 3,
    "Variant": 4,
}

SOFTWARE_TYPE_SCORE = {
    "utility": 1,
    "framework": 1,
    "server": 1,
    "web_application": 2,
    "mobile_app": 2,
    "package": 3,
    "extension": 3,
}


@dataclass
class CVEInAppWithCWEProfile(BaseProfile):
    """
        Profile for selecting CVEs that affect only a product that is an application.
    """
    cve_criteria: CVECriteria = field(default_factory=lambda: CVECriteria(valid=True))
    configuration_criteria: ConfigurationsCriteria = field(default_factory=lambda: app_config_criteria)
    weakness_criteria: WeaknessesCriteria = field(default_factory=lambda: weakness_criteria)


@dataclass
class ProductDetails:
    package_type: str
    vendor: str
    product: str
    software_type: str
    language: str

    def __post_init__(self):
        self.id = f"{self.vendor}_{self.product}"

    def to_dict(self):
        return {
            "vendor": self.vendor,
            "product": self.product,
            "software_type": self.software_type,
            "language": self.language
        }


@dataclass
class CWEProperties:
    id: int
    vulnerability_mapping: str
    abstraction: str


class DetailedCVELoader(JSONDefaultLoader):
    def __init__(
            self, product_lang_df_path: Path, product_sw_type_df_path: Path, cwe_properties_df_path: Path, **kwargs
    ):
        super().__init__(profile=CVEInAppWithCWEProfile, verbose=True, **kwargs)
        product_lang_df = pd.read_csv(product_lang_df_path)
        product_sw_type_df = pd.read_csv(product_sw_type_df_path)
        cwe_properties_df = pd.read_csv(cwe_properties_df_path)
        self.cwe_properties = {}

        for _, row in cwe_properties_df.iterrows():
            self.cwe_properties[row['cwe_id']] = CWEProperties(
                id=row['cwe_id'],
                vulnerability_mapping=row['vulnerability_mapping'],
                abstraction=row['abstraction']
            )
        print(f"Loaded {len(self.cwe_properties)} CWE properties")

        merged_df = pd.merge(product_lang_df, product_sw_type_df, on=["vendor", "product"], how="inner")
        merged_df.rename(columns={"type": "package_type"}, inplace=True)
        merged_df.dropna(subset=["language", "software_type"], inplace=True)
        print(f"Found {len(merged_df)} products with language and software type")
        self.products = {}

        for _, row in tqdm(merged_df.iterrows(), total=len(merged_df), desc="Loading products details."):
            row_dict = row[['vendor', 'product', 'package_type', 'software_type', 'language']].to_dict()
            product = ProductDetails(**row_dict)
            self.products[product.id] = product

    def __call__(self, *args, **kwargs):
        rows = []

        for entry in super().__call__(*args, **kwargs):
            row = {'cve_id': entry.id}
            cwe_id = self.select_cwe_id(weaknesses=entry.weaknesses)

            if not cwe_id:
                continue

            row['cwe_id'] = f"CWE-{cwe_id}"

            vulnerable_product = self.select_vulnerable_product(configurations=entry.configurations)

            if not vulnerable_product:
                continue

            row.update(vulnerable_product.to_dict())
            rows.append(row)

        df = pd.DataFrame(rows)
        print(f"Found {len(df)} CVEs with CWEs")
        df.to_csv(output_file_path, index=False)

    def select_cwe_id(self, weaknesses: Weaknesses) -> Optional[int]:
        best_cwe = (None, -1)

        for weakness in weaknesses:
            for cwe_id in weakness.ids:
                if cwe_id not in self.cwe_properties:
                    continue

                cwe_properties = self.cwe_properties[cwe_id]

                if cwe_properties.vulnerability_mapping == 'DISCOURAGED':
                    continue

                cwe_score = CWE_ABSTRACTION_SCORE[cwe_properties.abstraction]
                cwe_score += 1 if weakness.type == WeaknessType.Primary else 0

                if cwe_score > best_cwe[1]:
                    best_cwe = (cwe_id, cwe_score)

        return best_cwe[0]

    def select_vulnerable_product(self, configurations: Configurations) -> Optional[ProductDetails]:
        best_product = (None, -1)

        for vuln_prod in configurations.vulnerable_products:
            if vuln_prod.part != CPEPart.Application:
                continue

            product_id = f"{vuln_prod.vendor}_{vuln_prod.name}"

            if product_id not in self.products:
                continue

            product = self.products[product_id]
            product_score = SOFTWARE_TYPE_SCORE[product.software_type]
            product_score += 1 if product.package_type == 'github' else 0

            if product_score > best_product[1]:
                best_product = (product, product_score)

        return best_product[0]

if output_file_path.exists():
    df = pd.read_csv(output_file_path)
    print(df[["cwe_id"]].value_counts().head(25))
    print(df[["software_type", "language", "cwe_id"]].value_counts().head(25))
else:
    loader = DetailedCVELoader(
        product_lang_df_path=data_path / "rq1" / "products_language.csv",
        product_sw_type_df_path=data_path / "rq1" / "software_type.csv",
        cwe_properties_df_path=data_path / "rq1" / "cwe_properties.csv"
    )

    cve_dict = loader(data_path=Path("~/.nvdutils/nvd-json-data-feeds"), include_subdirectories=True)
    #print(f"Loaded {len(cve_dict)} CVEs")
