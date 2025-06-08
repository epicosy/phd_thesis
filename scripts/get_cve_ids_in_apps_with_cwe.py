import pandas as pd

from pathlib import Path
from typing import Optional
from dataclasses import dataclass, field

from cpelib.types.definitions import CPEPart

from nvdutils.common.enums.weaknesses import WeaknessType
from nvdutils.loaders.json.default import JSONDefaultLoader

from nvdutils.models.weaknesses import Weaknesses

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


@dataclass
class CVEInAppWithCWEProfile(BaseProfile):
    """
        Profile for selecting CVEs that affect only a product that is an application.
    """
    cve_criteria: CVECriteria = field(default_factory=lambda: CVECriteria(valid=True))
    configuration_criteria: ConfigurationsCriteria = field(default_factory=lambda: app_config_criteria)
    weakness_criteria: WeaknessesCriteria = field(default_factory=lambda: weakness_criteria)


def select_cwe_id(weaknesses: Weaknesses, cwe_properties: dict) -> Optional[int]:
    best_cwe = (None, -1)

    for weakness in weaknesses:
        for cwe_id in weakness.ids:
            if cwe_id not in cwe_properties:
                continue

            cwe_score = CWE_ABSTRACTION_SCORE[cwe_properties[cwe_id]['abstraction']]
            cwe_score += 1 if weakness.type == WeaknessType.Primary else 0

            if cwe_score > best_cwe[1]:
                best_cwe = (cwe_id, cwe_score)

    return best_cwe[0]


def get_cwe_ids_in_apps_with_cwe_df(nvd_data_path: Path, cwe_properties_path: Path) -> pd.DataFrame:
    rows = []
    loader = JSONDefaultLoader(profile=CVEInAppWithCWEProfile, verbose=True)
    cwe_properties_df = pd.read_csv(cwe_properties_path)
    allowed_cwe_df = cwe_properties_df[cwe_properties_df["vulnerability_mapping"] != 'DISCOURAGED']

    cwe_properties_dict = {row["cwe_id"]: row.to_dict() for _, row in allowed_cwe_df.iterrows()}

    for entry in loader(data_path=nvd_data_path, include_subdirectories=True):
        cwe_id = select_cwe_id(weaknesses=entry.weaknesses, cwe_properties=cwe_properties_dict)

        if not cwe_id:
            continue

        rows.append({
            'cve_id': entry.id,
            'cwe_id': f"CWE-{cwe_id}"
        })

    _df = pd.DataFrame(rows)
    print(f"Found {len(_df)} CVEs with CWEs")

    return _df


if output_file_path.exists():
    df = pd.read_csv(output_file_path)
else:
    df = get_cwe_ids_in_apps_with_cwe_df(
        nvd_data_path=Path("~/.nvdutils/nvd-json-data-feeds"),
        cwe_properties_path=data_path / "rq1" / "cwe_properties.csv"
    )

    df.to_csv(output_file_path, index=False)

print(f"Unique CWE-IDs: {len(df['cwe_id'].unique())}")
counts = df['cwe_id'].value_counts()
top_25 = counts.head(25)

print(f"Top 25 CWEs: {top_25}")
print(f"Top 25 Percentage: {top_25.sum() / counts.sum()}")
