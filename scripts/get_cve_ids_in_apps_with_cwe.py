import pandas as pd

from pathlib import Path
from typing import Optional, Dict
from dataclasses import dataclass, field

from pydantic_cwe.loader import Loader
from pydantic_cwe.models import Weakness
from cpelib.types.definitions import CPEPart

from nvdutils.common.enums.weaknesses import WeaknessType
from nvdutils.loaders.json.default import JSONDefaultLoader

from nvdutils.models.weaknesses import Weaknesses as NVDWeaknesses
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
    "Compound": 1,
    "Class": 2,
    "Base": 3,
    "Variant": 4,
}

TARGET_VULNERABILITY_MAPPINGS = ['Allowed-with-Review', 'Allowed']
TARGET_DETECTION_METHODS = {
    'Formal Verification', 'Automated Analysis', 'Automated Static Analysis', 'Automated Dynamic Analysis', 'Black Box',
    'White Box', 'Automated Static Analysis - Source Code', 'Fuzzing', 'Automated Static Analysis - Binary or Bytecode',
    'Dynamic Analysis with Automated Results Interpretation'
}

SOFTWARE_ATTACK_PATTERN_IDS = {
    21, 196, 226, 59, 510, 593, 102, 107, 60, 61, 62, 467, 22, 202, 207, 200, 208, 39, 77, 13, 162, 25, 26, 29, 27,
    28, 215, 74, 140, 663, 696, 94, 219, 384, 385, 389, 386, 387, 388, 466, 662, 701, 112, 20, 49, 16, 55, 565, 70,
    113, 121, 661, 133, 160, 36, 114, 115, 461, 480, 237, 664, 668, 87, 116, 150, 143, 144, 155, 637, 647, 648, 54,
    127, 215, 261, 462, 95, 545, 498, 546, 634, 639, 569, 568, 675, 117, 157, 158, 57, 65, 499, 501, 651, 634, 699,
    122, 1, 58, 17, 177, 263, 562, 563, 642, 650, 180, 58, 702, 201, 503, 123, 100, 10, 14, 24, 256, 42, 44, 45, 46,
    47, 67, 8, 9, 540, 124, 125, 482, 486, 487, 488, 489, 490, 528, 147, 666, 129, 130, 230, 197, 491, 231, 221, 229,
    492, 493, 494, 495, 496, 131, 137, 134, 41, 135, 67, 138, 15, 460, 182, 174, 178, 6, 148, 145, 218, 502, 151, 194,
    275, 598, 633, 697, 473, 459, 474, 475, 476, 477, 479, 485, 153, 126, 139, 597, 76, 128, 92, 267, 120, 3, 4, 43,
    52, 53, 64, 71, 72, 78, 79, 80, 154, 159, 132, 38, 471, 641, 616, 615, 695, 161, 141, 142, 166, 268, 81, 93, 481,
    571, 700, 165, 572, 655, 635, 11, 649, 636, 168, 35, 73, 169, 292, 285, 294, 295, 296, 297, 298, 299, 612, 613,
    618, 619, 300, 287, 301, 302, 303, 304, 305, 306, 307, 308, 309, 290, 291, 293, 643, 497, 149, 529, 573, 574, 575,
    576, 577, 580, 581, 85, 646, 694, 173, 103, 181, 222, 587, 501, 504, 654, 506, 175, 251, 252, 640, 660, 253, 101,
    193, 500, 176, 203, 270, 478, 51, 271, 146, 536, 578, 75, 184, 185, 186, 187, 533, 614, 657, 663, 696, 669, 188,
    167, 190, 191, 204, 37, 189, 621, 622, 623, 212, 111, 2, 48, 50, 620, 606, 682, 224, 312, 317, 318, 319, 320, 321,
    322, 323, 324, 325, 326, 327, 328, 329, 330, 331, 332, 313, 541, 170, 310, 472, 227, 469, 233, 104, 234, 30, 68,
    69, 240, 610, 242, 19, 23, 44, 41, 468, 63, 588, 18, 198, 199, 243, 244, 245, 247, 32, 86, 591, 18, 198, 199, 243,
    244, 245, 247, 32, 86, 592, 18, 198, 199, 209, 243, 244, 245, 247, 32, 86, 248, 136, 183, 250, 228, 83, 84, 40, 66,
    108, 109, 110, 470, 7, 676, 88, 272, 220, 105, 273, 274, 33, 34, 5, 276, 665, 277, 278, 201, 221, 279, 410, 407,
    383, 438, 444, 206, 443, 445, 446, 532, 538, 670, 672, 673, 678, 441, 442, 448, 452, 638, 456, 457, 458, 548, 549,
    542, 550, 551, 552, 556, 558, 564, 579, 698, 554, 179, 464, 465, 560, 555, 600, 652, 509, 645, 653, 561, 644, 586,
    594, 595, 596, 607, 582, 584, 603, 589, 590, 96, 690, 691, 692, 693
}


@dataclass
class CVEInAppWithCWEProfile(BaseProfile):
    """
        Profile for selecting CVEs that affect only a product that is an application.
    """
    cve_criteria: CVECriteria = field(default_factory=lambda: CVECriteria(valid=True))
    configuration_criteria: ConfigurationsCriteria = field(default_factory=lambda: app_config_criteria)
    weakness_criteria: WeaknessesCriteria = field(default_factory=lambda: weakness_criteria)


def get_code_related_weaknesses() -> Dict[int, Weakness]:
    cwe_loader = Loader()
    catalog = cwe_loader.load()

    weaknesses = {}

    for weakness in catalog.get_ordered_weaknesses():
        if weakness.status == 'Deprecated':
            continue

        if weakness.mapping_notes['Usage'] not in TARGET_VULNERABILITY_MAPPINGS:
            continue

        has_implementation_in_introductions = "Implementation" in weakness.get_introduction_phases()
        # some code-related weaknesses are introduced earlier (architecture/design) yet manifest strongly in code and still require code changes to fix.
        has_implementation_in_mitigations = "Implementation" in weakness.get_mitigations_phases()
        # multiple code-related signals
        has_code_examples = len(weakness.get_code_examples()) > 0
        has_detection_methods = len(TARGET_DETECTION_METHODS.intersection(weakness.get_detection_methods())) > 0
        has_software_attack_pattern = len(
            SOFTWARE_ATTACK_PATTERN_IDS.intersection(weakness.get_related_attack_pattern_ids())) > 0

        if has_implementation_in_introductions or has_implementation_in_mitigations:
            if has_code_examples or has_detection_methods or has_software_attack_pattern:
                weaknesses[weakness.id] = weakness

    return weaknesses


def select_cwe_id(weaknesses: NVDWeaknesses, cwe_properties: Dict[int, Weakness]) -> Optional[int]:
    best_cwe = (None, -1)

    for weakness in weaknesses:
        for cwe_id in weakness.ids:
            if cwe_id not in cwe_properties:
                continue

            cwe_abstraction = cwe_properties[cwe_id].abstraction
            cwe_score = CWE_ABSTRACTION_SCORE[cwe_abstraction]
            cwe_score += 1 if weakness.type == WeaknessType.Primary else 0

            if cwe_score > best_cwe[1]:
                best_cwe = (cwe_id, cwe_score)

    return best_cwe[0]


def get_cwe_ids_in_apps_with_cwe_df(nvd_data_path: Path) -> pd.DataFrame:
    rows = []
    loader = JSONDefaultLoader(profile=CVEInAppWithCWEProfile, verbose=True)
    cwe_properties_dict = get_code_related_weaknesses()

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
    df = get_cwe_ids_in_apps_with_cwe_df(nvd_data_path=Path("~/.nvdutils/nvd-json-data-feeds"))
    df.to_csv(output_file_path, index=False)

print(f"Unique CWE-IDs: {len(df['cwe_id'].unique())}")
counts = df['cwe_id'].value_counts()
top_25 = counts.head(25)

print(f"Top 25 CWEs: {top_25}")
print(f"Top 25 Percentage: {top_25.sum() / counts.sum()}")
