import argparse
import sys
import os
import platform
from urllib.parse import quote
import requests
import json
import yaml

def get_service():
    """
    Parse command-line arguments for fetching vulnerability information from NVD.
    
    Returns:
        dict: A dictionary of the command-line arguments and their values.
    """
    parser = argparse.ArgumentParser(
        description='Fetch vulnerability information from NVD through the command line',
        epilog='By rizzziom'
    )
    parser.add_argument('-a', '--api', metavar='key', help='An API key to use while querying the NVD')
    parser.add_argument('-c', '--cveid', metavar='string', help='Search CVE using ID')
    parser.add_argument('-k', '--keyword', metavar='string', help='Search CVE using keyword')
    parser.add_argument('-n', '--cpename', metavar='string', help='Search CVE using CPE name')
    parser.add_argument('-x', '--cweid', metavar='string', help='Search CVE using CWE ID')
    parser.add_argument('-r', '--resultsperpage', metavar='int', help='Specify the maximum number of CVE returned in a single response. [DEFAULT 2000]')
    parser.add_argument('-i', '--startindex', metavar='int', help='Display CVEs starting from specified index. [DEFAULT 0]')
    parser.add_argument('-v3', '--cvssv3severity', metavar='string', help='Filter results based on the CVSS v3 severity [LOW, MEDIUM, HIGH, CRITICAL]')
    parser.add_argument('-v2', '--cvssv2severity', metavar='string', help='Filter results based on the CVSS v2 severity [LOW, MEDIUM, HIGH]')
    parser.add_argument('-ot', '--txtfile', metavar='string', help='Save output in txt file')
    parser.add_argument('-oj', '--jsonfile', metavar='string', help='Save output in json file.')
    args = parser.parse_args()
    
    # Ensure that search parameters are provided if any results parameter is given
    if any([args.resultsperpage, args.startindex, args.cvssv3severity, args.cvssv2severity]) and not any([args.api, args.cveid, args.keyword, args.cpename, args.cweid]):
        print("Error: You must specify at least one parameter to search vulnerability")
        sys.exit(1)
    
    # Print help and exit if no arguments are provided
    if not any(vars(args).values()):
        parser.print_help()
        sys.exit(1)
    
    return vars(args)

def cpe2tocpe3(cpename):
    """
    Convert a CPE name from version 2.2 to version 2.3.

    Args:
        cpename (str): The CPE name to convert.

    Returns:
        str: The converted CPE name in version 2.3 format, or the original name if already in version 2.3 format.
    """
    if cpename.startswith('cpe:/'):
        return cpename.replace('cpe:/', 'cpe:2.3:', 1)
    elif cpename.startswith('cpe:2.3:'):
        return cpename
    else:
        raise ValueError("Invalid CPE name format.")

def encode_service(arguments_dictionary):
    """
    URL encode spaces, signs, and symbols in the service name and version to pass through an API.

    Args:
        arguments_dictionary (dict): The dictionary containing command-line arguments and their values.

    Returns:
        dict: The dictionary with URL-encoded values where necessary.
    """
    encoded_names = {}

    cpe_name = arguments_dictionary.get('cpename')
    if cpe_name:
        arguments_dictionary['cpename'] = cpe2tocpe3(cpe_name)
    
    for key, value in arguments_dictionary.items():
        if key not in ['api', 'txtfile', 'jsonfile'] and value:
            if key == 'cpename':
                encoded_names[key] = value
            elif key == 'cveid':
                encoded_names[key] = value.upper() if value.lower().startswith('cve-') else f'CVE-{value}'
            else:
                encoded_names[key] = quote(value)
    
    return encoded_names

def query_url(encoded_names):
    """
    Create a URL to query the NVD API.

    Args:
        encoded_names (dict): The dictionary containing URL-encoded argument names and values.

    Returns:
        str: The constructed URL for querying the NVD API.
    """
    base_url = 'https://services.nvd.nist.gov/rest/json/cves/2.0'
    
    if 'cvssv3severity' in encoded_names and 'cvssv2severity' in encoded_names:
        print("Enter either v3 severity or v2 severity")
        sys.exit(1)

    query_params = []
    for key, value in encoded_names.items():
        if value:
            if key == 'cveid':
                query_params.append(f"cveId={value}")
            elif key == 'keyword':
                query_params.append(f"keywordSearch={value}")
            elif key == 'cpename':
                query_params.append(f"cpeName={value}")
            elif key == 'cweid':
                query_params.append(f"cweId={value}")
            elif key == 'resultsperpage':
                query_params.append(f"resultsPerPage={value}")
            elif key == 'startindex':
                query_params.append(f"startIndex={value}")
            elif key == 'cvssv3severity':
                query_params.append(f"cvssV3Severity={value.upper()}")
            elif key == 'cvssv2severity':
                query_params.append(f"cvssV2Severity={value.upper()}")
    
    if not query_params:
        print("No valid query parameters provided")
        sys.exit(1)

    query_string = '&'.join(query_params)
    url = f"{base_url}?{query_string}"
    
    return url

def fetch_response(url):
    """
    Send the query URL to the API endpoint and get the JSON response.

    Args:
        url (str): The query URL to send to the API.

    Returns:
        list: A list containing the JSON response from the API.
    """
    args = get_service()
    
    # Determine API key and set header
    api_key = args.get('api')
    if not api_key:
        if os.path.isfile('api-key.yaml'):
            with open('api-key.yaml', 'r') as file:
                api_data = yaml.safe_load(file)
                api_key = api_data.get('apiKey')
        elif platform.system() in ["Windows", "Linux"]:
            api_key = os.getenv('API_KEY')
    
    if not api_key:
        print("No API key found. Aborting!")
        sys.exit(1)
    
    header = {'apiKey': api_key}
    response_list = []
    
    # Send GET request to the API URL with the API key in the header
    response = requests.get(url, headers=header)
    if response.status_code == 200:
        raw_response = response.json()
        response_list.append(raw_response)
    else:
        print(f"Failed to fetch: {response.status_code}")
    
    return response_list

def clean_up(raw_json_list):
    """
    Beautify the raw JSON response into usable data and display necessary information.

    Args:
        raw_json_list (list): A list of raw JSON responses from the API.

    Returns:
        tuple: A tuple containing cleaned information, total results, and start index.
    """
    clean_info = []
    
    for response in raw_json_list:
        try:
            total_results = response['resultsPerPage']
            start_index = response['startIndex']
        except KeyError:
            print("Error: Missing 'resultsPerPage' or 'startIndex' in the JSON response.")
            continue

        for vulnerability in response.get("vulnerabilities", []):
            cve_id = vulnerability.get("cve", {}).get("id", "N/A")
            published_date = vulnerability.get("cve", {}).get("published", "N/A")
            last_modified_date = vulnerability.get("cve", {}).get("lastModified", "N/A")
            descriptions = vulnerability.get("cve", {}).get("descriptions", [])
            english_description = next((desc["value"] for desc in descriptions if desc["lang"] == "en"), "N/A")

            reference_urls = [ref["url"] for ref in vulnerability.get("cve", {}).get("references", [])]

            clean_info.append((cve_id, published_date, last_modified_date, english_description, reference_urls))
    
    return clean_info, total_results, start_index

def make_tfile(filename):
    """
    Create a txt file and append the parsed information into it.

    Args:
        filename (str): The name of the file to create.
    """
    if not filename.endswith(".txt"):
        filename = filename.strip() + ".txt"
    
    print(f"Storing output in {filename}...")
    
    try:
        with open(filename, "wt") as f:
            snames = get_service()
            enames = encode_service(snames)  # Encoding the parameters
            qurl = query_url(enames)  # Creating URLs using the encoded parameters
            responses = fetch_response(qurl)  # Fetching responses through get requests with the query URLs
            datalist, tresults, sindex = clean_up(responses)  # Parsing the response to display the output
            
            f.write(f"Results Fetched: {tresults}\n")
            f.write(f"Start Index: {sindex}\n\n")
            for info in datalist:
                cve_id, pub_date, mod_date, desc, ref_urls = info
                f.write(f"CVE ID: {cve_id}\n")
                f.write(f"Published Date: {pub_date}\n")
                f.write(f"Last Modified Date: {mod_date}\n")
                f.write(f"English Description: {desc}\n")
                f.write("Reference URLs:\n")
                for url in ref_urls:
                    f.write(f"- {url}\n")
                f.write("\n\n")
                
        print("Done")
    except IOError as e:
        print(f"Error writing to file {filename}: {e}")

def make_jfile(filename):
    """
    Create a JSON file and append the parsed information into it.

    Args:
        filename (str): The name of the file to create.
    """
    if not filename.endswith('.json'):
        filename = filename.strip() + '.json'
    
    print(f"Storing output in {filename}...")
    
    try:
        with open(filename, "wt") as f:
            snames = get_service()
            enames = encode_service(snames)  # Encoding the parameters
            qurl = query_url(enames)  # Creating URLs using the encoded parameters
            raw_json = fetch_response(qurl)  # Fetching responses through get requests with the query URLs
            datalist, tresults, sindex = clean_up(raw_json)  # Parsing the response to display the output

            # Creating a dictionary of the information received from clean_up function
            output_data = {
                "resultsPerPage": tresults,
                "startIndex": sindex,
                "data": []
            }
            for info in datalist:
                cve_id, pub_date, mod_date, desc, ref_urls = info
                output_data["data"].append({
                    "cveId": cve_id,
                    "publishedDate": pub_date,
                    "lastModifiedDate": mod_date,
                    "englishDescription": desc,
                    "referenceUrls": ref_urls
                })
            json.dump(output_data, f, indent=4)
        print("Done")
    except IOError as e:
        print(f"Error writing to file {filename}: {e}")

def main():
    """
    The main function that displays necessary information.
    """
    snames = get_service()  # Getting parameters from the terminal

    txtfile = snames.get('txtfile')
    jsonfile = snames.get('jsonfile')

    if txtfile:
        make_tfile(txtfile.strip())

    if jsonfile:
        make_jfile(jsonfile.strip())

    if not txtfile and not jsonfile:
        enames = encode_service(snames)  # Encoding the parameters
        qurl = query_url(enames)  # Creating URLs using the encoded parameters
        responses = fetch_response(qurl)  # Fetching responses through get requests with the query URLs
        datalist, tresults, sindex = clean_up(responses)  # Parsing the response to display the output
        
        print(f"Results Fetched: {tresults}")
        print(f"Start Index: {sindex}\n")
        
        for info in datalist:
            cve_id, pub_date, mod_date, desc, ref_urls = info
            print("CVE ID:", cve_id)
            print("Published Date:", pub_date)
            print("Last Modified Date:", mod_date)
            print("English Description:", desc)
            print("Reference URLs:")
            for url in ref_urls:
                print("-", url)
            print()

if __name__ == "__main__":
    main()