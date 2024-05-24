# NEMESIS
Nemesis fetches vulnerability information from the National Vulnerability Database (NVD) using various query parameters provided via the command line. It supports fetching data in both JSON and TXT formats.

## Features
- Fetch CVE information based on various parameters like CVE ID, keyword, CPE name, CWE ID, and more.
- Support for both CVSS v2 and CVSS v3 severity filtering.
- Save output in either JSON or TXT format.

## Requirements
- Python 3.x
- `requests` library
- `PyYAML` library

## Installation
1. Clone the repository
```sh
git clone https://github.com/RIZZZIOM/nemesis.git
cd nemesis
```

2. Install the requirements
```sh
pip install -r requirements.txt
```

## Usage
### Command Line Arguments
- `-a`, `--api`: An API key to use while querying the NVD.
- `-c`, `--cveid`: Search CVE using ID.
- `-k`, `--keyword`: Search CVE using keyword.
- `-n`, `--cpename`: Search CVE using CPE name.
- `-x`, `--cweid`: Search CVE using CWE ID.
- `-r`, `--resultsperpage`: Specify the maximum number of CVEs returned in a single response. [DEFAULT 2000]
- `-i`, `--startindex`: Display CVEs starting from specified index. [DEFAULT 0]
- `-v3`, `--cvssv3severity`: Filter results based on the CVSS v3 severity [LOW, MEDIUM, HIGH, CRITICAL].
- `-v2`, `--cvssv2severity`: Filter results based on the CVSS v2 severity [LOW, MEDIUM, HIGH].
- `-ot`, `--txtfile`: Save output in TXT file.
- `-oj`, `--jsonfile`: Save output in JSON file.

### Example Commands
1. Fetch CVE information by CVE ID and save it as a JSON file:

```python
python3 nemesis.py -c 'CVE-2023-1234' -oj 'output.json'
```

2. Fetch cvssv3 CRITICAL CVE information by keyword and save it as a TXT file

```Python
python3 nemesis.py -k 'Microsoft Word 2007' -v3 'critical' -ot 'word.txt' 
```

### Running the Script
To run the script, use the following command:

```Python
python3 nemesis.py [options]
```
Replace `[options]` with the appropriate command line arguments listed above.

## Project Structure
- `nemesis.py`: The main script containing all the functions and the `main` function to execute the script.
- `api-key.yaml`: A YAML file to store the API key if not provided through the command line or environment variables.
- `requirements.txt`: A txt file containing libraries required to run the script.
- `LICENSE`: The file containing the MIT license for the project.
- `NEMESIS.pdf`: A detailed user guide providing instructions and examples for using nemesis.

## Contributing
Contributions are welcome! Please fork this repository and submit a pull request with your changes. Make sure to follow the existing coding style and include tests for any new features or bug fixes.

## User Guide
For more information about the nemesis project, please refer to the following [user guide](<NEMESIS.pdf>).

## License
This project is licensed under the MIT License. See the [LICENSE](LICENSE.txt) file for details.
