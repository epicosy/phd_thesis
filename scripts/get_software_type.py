import json
import pandas as pd

from typing import List
from pathlib import Path
from typing import Optional
from pydantic import AnyUrl
from collections import Counter

from cpelib.types.item import CPEItem
from cpelib.types.reference import Reference
from cpelib.core.loaders.xml import XMLLoader


root_path = Path(__file__).parent.parent
rq1_data_path = root_path / "data" / "rq1"
domain_sw_type_mapping_path = rq1_data_path / "domain_sw_type_mapping.json"
keywords_sw_type_mapping_path = rq1_data_path / "keywords_sw_type_mapping.json"
target_sw_type_mapping_path = rq1_data_path / "target_sw_type_mapping.json"
output_file_path = rq1_data_path / "software_type.csv"


# TODO: websites like [https://marketplace.eclipse.org/, mvnrepository.com, https://sourceforge.net/] could be used to
#  fetch products by category and match by name/URL
DOMAIN_SW_TYPE_MAPPING = json.load(open(domain_sw_type_mapping_path))
KEYWORDS_MAPPING = json.load(open(keywords_sw_type_mapping_path))
TGT_SW_MAPPING = json.load(open(target_sw_type_mapping_path))
TGT_SW_ALL = [_tgt_sw_val for _, _tgt_sw_vals in TGT_SW_MAPPING.items() for _tgt_sw_val in _tgt_sw_vals]


def label_target_software(product_name: str, tgt_sw: str) -> Optional[str]:
    for tgt_sw_type, mappings in TGT_SW_MAPPING.items():
        if product_name in mappings:
            return None
        if tgt_sw in mappings:
            return tgt_sw_type

    return None


def label_product_name(product_name: str) -> Optional[str]:
    for sep in ['_', '-', ':', '.']:
        terms = set(product_name.split(sep))

        if len(terms) == 1:
            continue

        for label, keywords in KEYWORDS_MAPPING.items():
            if terms.intersection(keywords):
                return label

    return None


def get_label_from_references(product_name: str, references: List[Reference]) -> Optional[str]:
    for reference in references:
        obj_ref = AnyUrl(reference.href)

        if obj_ref.host in DOMAIN_SW_TYPE_MAPPING and product_name not in TGT_SW_ALL:
            return DOMAIN_SW_TYPE_MAPPING[obj_ref.host] + "_ref"

    return None


def label_cpe(cpe_item: CPEItem) -> str:
    label = None

    if cpe_item.references:
        label = get_label_from_references(cpe_item.cpe.product, cpe_item.references)

    if not label:
        if cpe_item.cpe.target_sw and cpe_item.cpe.target_sw not in ['-', '*']:
            label = label_target_software(cpe_item.cpe.product, cpe_item.cpe.target_sw)

        if not label:
            label = label_product_name(cpe_item.cpe.product)

    return label


def get_software_type_dataset_df() -> pd.DataFrame:
    # dataset from https://ksiresearch.org/seke/seke20paper/paper047.pdf
    # request access to the dataset from the authors https://github.com/onniegit/Software-Type-Dataset
    _columns = ["vendor", "product", "software_type"]
    path = Path("~/projects/loopholes/Software-Type-Dataset/NVD all.csv").expanduser()
    _df = pd.read_csv(path)
    _df.rename(columns={"vendor_name": "vendor", "product_name": "product"}, inplace=True)
    print(f"Loaded {len(_df)} entries")
    _df.drop_duplicates(inplace=True, subset=_columns)
    _df.dropna(subset=_columns, inplace=True)
    print(f"Found {len(_df)} unique software types")
    _df = _df[_df['software_type'] != 'operating system']
    print(f"{len(_df)} entries left after removing operating system")
    # change browser to utility due to its supporting role in accessing online resources
    _df.loc[_df['software_type'] == 'browser', 'software_type'] = 'utility'
    # change middleware to library as it is often delivered as a library
    _df.loc[_df['software_type'] == 'middleware', 'software_type'] = 'library'
    # rename web application to web_app
    _df.loc[_df['software_type'] == 'web application', 'software_type'] = 'web_app'

    return _df[_columns]


def get_software_type_from_cpe_dict(output_file: Path) -> pd.DataFrame:
    # https://nvd.nist.gov/products/cpe
    # XML file should be placed under '~/.cpelib/official-cpe-dictionary_v2.3.xml' or provide the path to the file
    loader = XMLLoader()
    cpe_rows = []

    for cpe_item in loader():
        if cpe_item.deprecated:
            continue

        cpe_item_dict = cpe_item.cpe.model_dump()
        cpe_item_dict['software_type'] = label_cpe(cpe_item)
        cpe_rows.append(cpe_item_dict)

    cpe_df = pd.DataFrame(cpe_rows)
    cpe_df.dropna(inplace=True, subset=['software_type'])

    new_rows = []

    for group, rows in cpe_df.groupby(["vendor", "product"]):
        vendor, product = group
        row = {"vendor": vendor, "product": product}

        software_type_list = rows['software_type'].unique().tolist()

        if len(software_type_list) == 1:
            row['software_type'] = software_type_list[0]
        else:
            if len(software_type_list) > 2:
                row['software_type'] = Counter(rows['software_type'].tolist()).most_common(1)[0][0]
            else:
                for el in software_type_list:
                    if "_ref" in el:
                        row['software_type'] = el
                        break
                else:
                    row['software_type'] = None
                    print(f"Found multiple software types for {group}: {list(software_type_list)}")

        new_rows.append(row)

    _sw_type_df = pd.DataFrame(new_rows)
    _sw_type_df.to_csv(output_file, index=False)

    print(_sw_type_df['software_type'].value_counts())

    return _sw_type_df


def select_software_type(x: str, y: str) -> str:
    """
        x: cpe auto label
        y: software type dataset
    """
    if pd.isna(x):
        return y

    if "_ref" in x:
        return x.replace("_ref", "")

    if pd.isna(y):
        return x

    if x == y:
        return x

    if y == 'framework':
        # picks the software with lower granularity
        return x if x in ['extension', 'library'] else y

    if y == 'utility':
        # picks the software that is most specific
        return x if x == 'mobile_app' else y

    if y == 'server':
        # picks the software that is most specific
        return x if x == 'library' else y

    if y == 'web_app':
        return y

    if y == 'library':
        return y

    raise ValueError(f"Unexpected combination of software types: {x} and {y}")


if output_file_path.exists():
    software_type_df = pd.read_csv(output_file_path)
else:
    cpe_software_type_df = get_software_type_from_cpe_dict(output_file_path)
    software_type_dataset_df = get_software_type_dataset_df()

    # check disagreement between labels
    software_type_df = pd.merge(cpe_software_type_df, software_type_dataset_df, on=["vendor", "product"], how="outer")
    software_type_df["software_type"] = software_type_df.apply(
        lambda x: select_software_type(x['software_type_x'], x['software_type_y']), axis=1
    )

    software_type_df.drop(columns=["software_type_x", "software_type_y"], inplace=True)
    software_type_df.to_csv(rq1_data_path / "software_type.csv", index=False)

print(software_type_df['software_type'].value_counts())
