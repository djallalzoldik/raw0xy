import requests
import sys
import os
import pyfiglet
import re
import urllib3
from concurrent.futures import ThreadPoolExecutor, as_completed
from requests.exceptions import RequestException

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def split_on_empty_lines(text):
    """Splits text on consecutive empty lines."""
    blank_line_regex = r"(?:\r?\n){2,}"
    return re.split(blank_line_regex, text.strip())

def display_help():
    ascii_banner = pyfiglet.figlet_format("raw0xy")
    print(f"{ascii_banner}\t\t\tBeta v1.0")
    print("""Usage: python3 raw0xy.py <folder_path> <ip:port>
    Processes all .txt files in the specified folder.""")

def request(method, url, headers, body=None, proxy=None):
    session = requests.Session()
    session.proxies = {'http': proxy, 'https': proxy}
    try:
        response = session.request(method, url, headers=headers, data=body, verify=False)
        print(f"{method} request to {url} completed with status code {response.status_code}")
        return response.status_code
    except RequestException as e:
        print(f"Request failed for {url}: {e}")
        return None

def process_headers(headers_list, host_index):
    """Removes the request line and Host header, returning the remaining headers."""
    headers_list.pop(0)
    headers_list.pop(host_index - 1)
    return headers_list

def parse_headers(raw_headers):
    """Parses raw headers list into a dictionary."""
    headers = {}
    for line in raw_headers:
        key, value = line.split(":", 1)
        headers[key.strip()] = value.strip()
    return headers

def parse_body(parts):
    """Combines body parts into a single body string."""
    return "\r\n\r\n".join(parts[1:]) if len(parts) > 1 else parts[0]

def handle_request(file_path, proxy_ip):
    with open(file_path, 'r', errors='ignore') as f:
        raw_data = f.read()

    parts = split_on_empty_lines(raw_data)
    if 'Transfer-Encoding' in parts[0]:
        print(f"Unsupported format in file {file_path}: Transfer-Encoding: chunked")
        return

    request_line = parts[0].splitlines()
    method, query = request_line[0].split()[:2]
    host_index = next(i for i, line in enumerate(request_line) if line.lower().startswith("host:"))
    hostname = f"{request_line[host_index].split()[1]}:443"
    url = f"https://{hostname}{query}"

    body = parse_body(parts) if len(parts) > 1 else "" if method != 'GET' else None
    raw_headers = process_headers(request_line, host_index)
    headers = parse_headers(raw_headers)

    request(method, url, headers, body, proxy_ip)

def main():
    if len(sys.argv) < 3:
        display_help()
        sys.exit(1)

    folder_path = sys.argv[1]
    proxy_ip = sys.argv[2]

    # Get all .txt files in the specified folder
    files = [os.path.join(folder_path, f) for f in os.listdir(folder_path) if f.endswith(".txt")]
    if not files:
        print("No .txt files found in the specified folder.")
        sys.exit(1)

    # Using ThreadPoolExecutor to handle threads
    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = [executor.submit(handle_request, file_path, proxy_ip) for file_path in files]

        for future in as_completed(futures):
            future.result()  # This will raise exceptions if any occurred in a thread

if __name__ == "__main__":
    main()
