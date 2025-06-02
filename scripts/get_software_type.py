import pandas as pd

from pathlib import Path
from typing import Optional
from collections import Counter

from cpelib.types.cpe import CPE
from cpelib.core.loaders.xml import XMLLoader


# TODO: for this kind of product should be easy to tell if it is a mobile app or not, but considering the domain in the
#  references, e.g.	https://play.google.com it is a 100% match
TGT_SW_MOBILE_APP_MAPPING = ['iphone_os', 'android']
MOBILE_APP_KEYWORDS = [
    'mobile', 'android', 'iphone', 'sms'
]

EXTENSION_KEYWORDS = [
    'plugin', 'plugin', 'extension', 'extensions', 'theme', 'themes', 'widget', 'widgets', 'addon', 'addons', 'add-on',
    'add-ons', 'template', 'templates', 'wp', 'wordpress', 'drupal', 'component'
]
TGT_SW_EXTENSION_MAPPING = ['wordpress', 'drupal', 'typo3', 'prestashop', 'joomla\!', 'pimcore']

TGT_SW_PACAKGE_MAPPING = ['silverstripe', 'jenkins', 'laravel', 'fastify', 'node.js', 'django']
PACKAGE_KEYWORDS = [
    'library', 'libraries', 'lib', 'sdk', 'core', 'module', 'package', 'development_kit', 'api', 'middleware',
]

SERVER_KEYWORDS = [
    'daemon', 'service', 'monitor', 'agent', 'server', 'webserver', 'webserver', 'client', 'webservice', 'webservices',
    'database', 'gateway', 'cloud', 'endpoint'
]

FRAMEWORK_KEYWORDS = [
    'framework',
]

WEB_APPLICATION_KEYWORDS = [
    "cms", "crm", 'portal', 'platform', 'forum', 'blog',
]

UTILITY_KEYWORDS = [
    'utility', 'utilities', 'tool', 'tools', 'cli', 'commandline', 'commandline-line-interface', 'script', 'scripts',
    'manager', 'suite', 'browser'
]

TGT_SW_MAPPING = {
    "extension": TGT_SW_EXTENSION_MAPPING,
    "package": TGT_SW_PACAKGE_MAPPING,
    "mobile_app": TGT_SW_MOBILE_APP_MAPPING
}

KEYWORDS_MAPPING = {
    "extension": EXTENSION_KEYWORDS,
    "package": PACKAGE_KEYWORDS,
    "framework": FRAMEWORK_KEYWORDS,
    "utility": UTILITY_KEYWORDS,
    "server": SERVER_KEYWORDS,
    "web_application": WEB_APPLICATION_KEYWORDS,
    "mobile_app": MOBILE_APP_KEYWORDS
}


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

def label_cpe(cpe: CPE) -> str:
    label = None

    if cpe.target_sw and cpe.target_sw not in ['-', '*']:
        label = label_target_software(cpe.product, cpe.target_sw)

    if not label:
        label = label_product_name(cpe.product)

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
    # change middleware to package as it is often delivered as a package
    _df.loc[_df['software_type'] == 'middleware', 'software_type'] = 'package'
    # rename web application to web_application
    _df.loc[_df['software_type'] == 'web application', 'software_type'] = 'web_application'

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
        cpe_item_dict['software_type'] = label_cpe(cpe_item.cpe)
        cpe_rows.append(cpe_item_dict)

    cpe_df = pd.DataFrame(cpe_rows)
    cpe_df.dropna(inplace=True, subset=['software_type'])

    new_rows = []

    for group, rows in cpe_df.groupby(["vendor", "product"]):
        vendor, product = group
        row = {"vendor": vendor, "product": product}

        software_type_list = rows['software_type'].unique()

        if len(software_type_list) == 1:
            row['software_type'] = software_type_list[0]
        else:
            if len(software_type_list) > 2:
                row['software_type'] = Counter(rows['software_type'].list()).most_common(1)[0][0]
            else:
                # TODO: implement logic to pick the most appropriate software type
                print(f"Found multiple software types for {group}: {list(software_type_list)}")

        new_rows.append(row)

    _sw_type_df = pd.DataFrame(new_rows)
    _sw_type_df.to_csv(output_file, index=False)

    return _sw_type_df


def select_software_type(x: str, y: str) -> str:
    if pd.isna(x):
        return y
    if pd.isna(y):
        return x

    if x == y:
        return x

    if y == 'framework':
        # picks the software with lower granularity
        return x if x in ['extension', 'package'] else y

    if y == 'utility':
        # picks the software that is most specific
        return x if x == 'mobile_app' else y

    if y == 'server':
        # picks the software that is most specific
        return x if x == 'package' else y

    if y == 'web_application':
        return y

    if y == 'package':
        return y

    raise ValueError(f"Unexpected combination of software types: {x} and {y}")


root_path = Path(__file__).parent.parent
rq1_data_path = root_path / "data" / "rq1"
output_file_path = rq1_data_path / "software_type.csv"

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
