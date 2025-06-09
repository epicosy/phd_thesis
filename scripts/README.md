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
3. Load CWE properties data including vulnerability mapping and abstraction
4. Filter the CVEs based on the defined criteria
5. For each matching CVE:
   - Extract the CWE IDs associated with the CVE
   - Select the most appropriate CWE ID based on:
     - Vulnerability mapping (skipping DISCOURAGED mappings)
     - Abstraction level (preferring more specific abstractions like Variant over more general ones like Class)
     - Weakness type (preferring Primary weaknesses)
6. Save the results (CVE ID and CWE ID) to a CSV file in the data/rq1 directory

**Dependencies**:
- pandas
- nvdutils
- cpelib

### 2. get_products_language.py

**Purpose**: This script maps software products to their programming languages using package URL (purl) to CPE mappings and GitHub repository information. It categorizes programming languages into primary (general-purpose) and secondary (domain-specific) languages based on the classification defined in language_extension_mapping.json.

**Algorithm**:
1. Load purl-to-CPE mappings from a SQLite database
2. Load language classification from language_extension_mapping.json, which defines:
   - Primary languages: General-purpose, Turing-complete languages (e.g., PHP, C, Java, Python)
   - Secondary languages: Domain-specific, executable languages (e.g., SQL, MATLAB, R)
3. Create a DataFrame with vendor-product-purl mappings
4. Map packages to programming languages using:
   - A predefined mapping of package types to languages (e.g., maven → Java, pypi → Python)
   - For GitHub repositories, query the GitHub API to get repository languages
5. For GitHub repositories, select the appropriate language based on priority rules:
   - First, check if the main language is in the primary languages list
   - If not, check if the second most common language is in the primary languages list
   - If still not found, check if the main language is in the secondary languages list
   - If still not found, check if the second language is in the secondary languages list
   - If no suitable language is found, mark as 'N/A'
6. Filter the mappings to include only products that appear in the CVE dataset
7. For products without language information from the package type mapping:
   - If they have GitHub repository information, query the GitHub API to get the language using the priority rules
8. Save the results to a CSV file in the data/rq1 directory

**Dependencies**:
- pandas
- tqdm
- gitlib
- cpeparser
- packageurl
- sqlite3
- json

**Requirements**:
- GitHub API token (set as GITHUB_TOKEN environment variable)
- Access to a purl2cpe.db SQLite database
- language_extension_mapping.json file in data/rq1 directory

### 3. get_software_type.py

**Purpose**: This script categorizes software products into different types (e.g., extension, package, mobile_app, framework, utility, server, web_application) based on CPE data and a research dataset.

**Algorithm**:
1. Load mapping files for software type categorization:
   - domain_sw_type_mapping.json: Maps domain names to software types
   - keywords_sw_type_mapping.json: Maps keywords to software types
   - target_sw_type_mapping.json: Maps target software to software types
2. Extract software type information from two sources:
   - The official CPE dictionary from NVD
   - A research dataset from a published paper
3. Label software products based on:
   - References in CPE data (using domain mappings)
   - Target software information in CPE data
   - Product name analysis using predefined keywords
4. Resolve conflicts when the two sources disagree on software type
5. Save the results to a CSV file in the data/rq1 directory

**Dependencies**:
- pandas
- cpelib
- pathlib
- collections (Counter)
- pydantic

**Requirements**:
- Access to the official CPE dictionary XML file
- Access to the Software-Type-Dataset (referenced in the script)
- Mapping files in data/rq1 directory:
  - domain_sw_type_mapping.json
  - keywords_sw_type_mapping.json
  - target_sw_type_mapping.json

### 4. create_dataset.py

**Purpose**: This script creates a consolidated dataset by combining CVE-CWE data with product details, including software type and programming language information.

**Algorithm**:
1. Load product language data from get_products_language.py output
2. Load software type data from get_software_type.py output
3. Merge the product language and software type data to create a product details dictionary
4. Load CVE-CWE data from get_cve_ids_in_apps_with_cwe.py output
5. For each CVE-CWE pair:
   - Load the full CVE data from the NVD JSON data feeds
   - Extract the vulnerable products that are applications
   - Select the most appropriate vulnerable product based on:
     - Software type (using a scoring system that prioritizes certain types)
     - Package type (giving preference to GitHub repositories)
   - Extract programming language information:
     - Attempt to extract language from CVE description by:
       - Identifying file names with known extensions in the description
       - Mapping file extensions to programming languages
       - Determining the most likely language based on frequency
     - If not available, fallback to use the language from product details
   - Create a record with CVE ID, CWE ID, vendor, product, software type, and language information
6. Save the consolidated dataset to a CSV file in the data/rq1 directory

**Dependencies**:
- pandas
- tqdm
- nvdutils
- cpelib

### 5. plots_rq1.py

**Purpose**: This script generates a Sankey diagram showing the relationship between software types, programming languages, and CWEs from the collected vulnerability data.

**Algorithm**:
1. Load consolidated data from the dataset.csv file
2. Create data for the Sankey diagram by:
   - Grouping by software_type, language, and cwe_id
   - Filtering to include only relationships with significant counts
   - Creating unique lists of nodes for each category
3. Apply a military HUD-style theme to the diagram
4. Generate link colors based on the source node's layer
5. Create and configure the Sankey diagram using Plotly
6. Add grid lines and other visual elements
7. Save the diagram as a PNG image in the results/rq1 directory

**Dependencies**:
- pandas
- plotly
- os

**Output**:
- A Sankey diagram saved as `sankey_software_language_cwe.png` in the results/rq1 directory

## Programming Language Classification

The script `get_products_language.py` uses a classification system for programming languages defined in `language_extension_mapping.json`. This classification is used to prioritize which language to associate with a software product when multiple languages are detected. The languages are categorized as follows:

### Primary Languages (General-Purpose)

These are languages designed to build a broad range of software systems, not limited to a particular domain or task. They are Turing-complete and expressive enough to write systems software, web servers, tools, games, and more.

Examples include:
- PHP, C, Java, Python, JavaScript
- C++, C#, Ruby, Go, Rust
- Kotlin, Swift, TypeScript, Perl
- Scala, Haskell, Clojure, Erlang
- Visual Basic, COBOL, Fortran, Ada

### Secondary Languages (Domain-Specific)

These are languages that are Turing-complete or executable, but tailored for a specific problem domain, like smart contracts, scientific modeling, query extensions, or visual computing.

Examples include:
- SQL, TSQL, PLpgSQL (database query languages)
- R, MATLAB, Mathematica (scientific/statistical computing)
- Shell, PowerShell (system scripting)
- Solidity (smart contracts)
- TeX (document typesetting)

> Special Notes:
> - Starlark: Technically Turing-complete, but execution is managed by the Bazel build tool 
> - TeX: Technically executable within a TeX engine that processes markup and generates formatted output
> - Hack: A PHP dialect mainly used by Facebook
> - R: Primarily used for statistical computing
> - MATLAB: Primarily used for numerical computing
> - Mathematica: Powered by the Wolfram Language, used mainly in mathematics and scientific computation

### Non-Executable Languages (Not Included in Classification)

These are syntaxes or languages that do not support general-purpose execution — typically declarative, stylistic, or templating languages that cannot express control flow or computation fully (i.e., not Turing-complete).

Examples include:
- HTML, CSS, SCSS, Less, Stylus, Roff (markup and styling)
- YAML, JSON, TOML, CSV (data formats)
- Markdown, MDX (document formats)
- Jinja, Mustache, Twig, Blade, EJS (templating)
- HCL, Puppet, Nix (configuration)
> **Nix** is used to define package builds and system configurations, but the actual execution of these definitions is handled by the Nix package manager and build system.


### Not Languages (Not Included in Classification)

These entries are not programming languages in a strict sense. They may be frameworks, build systems, configuration files, markup or packaging formats, UI frameworks, or meta-languages.

Examples include:
- Dockerfile, Batchfile, Makefile, CMake, BitBake, RPM Spec, Inno Setup (build/setup systems/scripts)
- Jupyter Notebook, Rich Text Format, Gettext Catalog, (data/document formats)
- Vue, Svelte, ASP.NET, ASP, Classic ASP, JetBrains MPS, Astro, CUDA, Lex, LLVM, ASL, LabVIEW (infra, tools, frameworks/platforms)

> **CUDA** is not a language itself but rather a parallel computing platform and API.

## Usage

The scripts are designed to be run in sequence:

1. First run `get_cve_ids_in_apps_with_cwe.py` to extract CVE data for applications with CWEs
2. Then run `get_products_language.py` to map the products from the CVE data to their programming languages
3. Run `get_software_type.py` to categorize the software products into different types
4. Run `create_dataset.py` to create a consolidated dataset combining CVE-CWE data with product details
5. Finally run `plots_rq1.py` to generate visualizations of the relationships between software types, languages, and CWEs

The output files are saved in the following directories:
- `data/rq1`:
  - `cve_ids_in_apps_with_cwe.csv`: Contains CVE IDs and CWE IDs
  - `products_language.csv`: Contains product information mapped to programming languages
  - `software_type.csv`: Contains product information mapped to software types
  - `dataset.csv`: Contains consolidated data with CVE IDs, CWE IDs, vendors, products, software types, and languages
- `results/rq1`:
  - `sankey_software_language_cwe.png`: Sankey diagram showing relationships between software types, languages, and CWEs
