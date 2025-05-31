import pandas as pd
from pathlib import Path
from dataclasses import dataclass, field

from cpelib.types.definitions import CPEPart

from nvdutils.common.enums.weaknesses import WeaknessType
from nvdutils.loaders.json.default import JSONDefaultLoader

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

@dataclass
class CVEInAppWithCWEProfile(BaseProfile):
    """
        Profile for selecting CVEs that affect only a product that is an application.
    """
    cve_criteria: CVECriteria = field(default_factory=lambda: CVECriteria(valid=True))
    configuration_criteria: ConfigurationsCriteria = field(default_factory=lambda: app_config_criteria)
    weakness_criteria: WeaknessesCriteria = field(default_factory=lambda: weakness_criteria)


loader = JSONDefaultLoader(verbose=True, profile=CVEInAppWithCWEProfile)
cve_dict = loader.load(Path("~/.nvdutils/nvd-json-data-feeds"), include_subdirectories=True)

print(f"Loaded {len(cve_dict)} CVEs")

rows = []

for cve_id, entry in cve_dict.entries.items():
    cwe_ids = set([cid for weakness in entry.weaknesses.primary for cid in weakness.ids])
    vulnerable_products = set(p for p in entry.configurations.vulnerable_products if p.part == CPEPart.Application)

    if len(cwe_ids) == 0:
        continue

    if len(vulnerable_products) == 0:
        continue

    cwe_id = cwe_ids.pop() # TODO: implement logic to pick the most appropriate CWE-ID
    vulnerable_product = vulnerable_products.pop() # TODO: implement logic to pick the most appropriate product

    rows.append({
        "cve_id": cve_id,
        "cwe_id": cwe_id,
        "vendor": vulnerable_product.vendor,
        "product": vulnerable_product.name
    })


df = pd.DataFrame(rows)
print(f"Found {len(df)} CVEs with CWEs")
df.to_csv(output_file_path, index=False)
