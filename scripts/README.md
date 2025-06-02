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
3. Load product language data from get_products_language.py output
4. Load software type data from get_software_type.py output
5. Load CWE properties data including vulnerability mapping and abstraction
6. Filter the CVEs based on the defined criteria
7. For each matching CVE:
   - Extract the CWE IDs associated with the CVE
   - Select the most appropriate CWE ID based on:
     - Vulnerability mapping (skipping DISCOURAGED mappings)
     - Abstraction level (preferring more specific abstractions like Variant over more general ones like Class)
     - Weakness type (preferring Primary weaknesses)
   - Extract the vulnerable products that are applications
   - Select the most appropriate vulnerable product based on:
     - Software type (using a scoring system that prioritizes certain types)
     - Package type (giving preference to GitHub repositories)
   - Create a record with CVE ID, CWE ID, vendor, and product information
8. Save the results to a CSV file in the data/rq1 directory

**Dependencies**:
- pandas
- tqdm
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

### 3. get_software_type.py

**Purpose**: This script categorizes software products into different types (e.g., extension, package, mobile_app, framework, utility, server, web_application) based on CPE data and a research dataset.

**Algorithm**:
1. Define mappings and keywords for different software types
2. Extract software type information from two sources:
   - The official CPE dictionary from NVD
   - A research dataset from a published paper
3. Label software products based on:
   - Target software information in CPE data
   - Product name analysis using predefined keywords
4. Resolve conflicts when the two sources disagree on software type
5. Save the results to a CSV file in the data/rq1 directory

**Dependencies**:
- pandas
- cpelib
- pathlib
- collections (Counter)

**Requirements**:
- Access to the official CPE dictionary XML file
- Access to the Software-Type-Dataset (referenced in the script)

## Usage

The scripts are designed to be run in sequence:

1. First run `get_cve_ids_in_apps_with_cwe.py` to extract CVE data for applications with CWEs
2. Then run `get_products_language.py` to map the products from the CVE data to their programming languages
3. Finally run `get_software_type.py` to categorize the software products into different types

The output files are saved in the `data/rq1` directory:
- `cve_ids_in_apps_with_cwe.csv`: Contains CVE IDs, CWE IDs, vendors, and products
- `products_language.csv`: Contains product information mapped to programming languages
- `software_type.csv`: Contains product information mapped to software types
