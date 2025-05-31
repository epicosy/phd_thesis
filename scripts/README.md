# Scripts Documentation

This directory contains scripts used for data collection and processing as part of the PhD thesis research. The scripts are designed to extract and analyze vulnerability data from the National Vulnerability Database (NVD) and map software products to their programming languages.

## Scripts Overview

### 1. get_cve_ids_in_apps_with_cwe.py

**Purpose**: This script extracts CVE (Common Vulnerabilities and Exposures) data for applications that have associated CWE (Common Weakness Enumeration) identifiers.

**Algorithm**:
1. Define criteria for filtering CVEs:
   - Only include valid CVE entries
   - Only include CVEs that affect applications (not operating systems or hardware)
   - Only include CVEs with primary weakness types (CWEs)
2. Load CVE data from the NVD JSON data feeds using the nvdutils library
3. Filter the CVEs based on the defined criteria
4. For each matching CVE:
   - Extract the CWE IDs associated with the CVE
   - Extract the vulnerable products that are applications
   - Select one CWE ID and one vulnerable product (currently using a simple selection method)
   - Create a record with CVE ID, CWE ID, vendor, and product information
5. Save the results to a CSV file in the data/rq1 directory

**Dependencies**:
- pandas
- nvdutils
- cpelib

### 2. get_products_language.py

**Purpose**: This script maps software products to their programming languages using package URL (purl) to CPE mappings and GitHub repository information.

**Algorithm**:
1. Load purl-to-CPE mappings from a SQLite database
2. Create a DataFrame with vendor-product-purl mappings
3. Map packages to programming languages using:
   - A predefined mapping of package types to languages (e.g., maven → Java, pypi → Python)
   - For GitHub repositories, query the GitHub API to get the primary language
4. Filter the mappings to include only products that appear in the CVE dataset
5. For products without language information from the package type mapping:
   - If they have GitHub repository information, query the GitHub API to get the language
6. Save the results to a CSV file in the data/rq1 directory

**Dependencies**:
- pandas
- tqdm
- gitlib
- cpeparser
- packageurl
- sqlite3

**Requirements**:
- GitHub API token (set as GITHUB_TOKEN environment variable)
- Access to a purl2cpe.db SQLite database

## Usage

The scripts are designed to be run in sequence:

1. First run `get_cve_ids_in_apps_with_cwe.py` to extract CVE data for applications with CWEs
2. Then run `get_products_language.py` to map the products from the CVE data to their programming languages

The output files are saved in the `data/rq1` directory:
- `cve_ids_in_apps_with_cwe.csv`: Contains CVE IDs, CWE IDs, vendors, and products
- `products_language.csv`: Contains product information mapped to programming languages