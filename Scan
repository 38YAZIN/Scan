import requests
import re
import concurrent.futures
import random
from urllib.parse import urljoin, urlparse
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

PURPLE = '\033[95m'
ENDC = '\033[0m'
BOLD = '\033[1m'

ASCII_ART = f"""{PURPLE}
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⣤⡴⠂⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣠⣴⣿⠟⠉⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣠⣶⣿⣿⣿⡅⠀⠀⠀⠀⠀⠀⠀⠀⢀⣀⣀⣀⣀⣀⣀⣀⣀⣀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣠⣤⣤⣤⣤⣴⣿⣿⣿⣿⣯⣤⣶⣶⣾⣿⣶⣶⣿⣿⣿⣿⣿⡿⠿⠟⠛⠉⠉⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠐⠉⠁⠈⣹⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣷⣶⣶⣶⠶⠶⠦⠄⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣠⣾⡿⠟⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣷⣦⡀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣴⣾⣿⣟⣡⣤⣾⣿⣿⣿⣿⣿⣿⢏⠉⠛⣿⣿⣿⣿⣿⣿⣿⣿⣿⡻⢿⣿⣿⣦⡀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⣀⣤⣶⣾⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠃⠈⠻⡄⠁⠀⢸⣿⣿⣿⣿⣿⣿⣿⣿⣿⣆⠈⠙⠻⣿⣆⠀⠀⠀⠀
⠀⠀⠀⠀⢰⣿⣿⣿⣿⡿⠛⠉⠉⠉⠛⠛⠛⠛⠋⠁⠀⠀⠀⠁⠀⣠⣾⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣧⠀⠀⠈⠙⢧⠀⠀⠀
⠀⠀⠀⠀⠀⠙⠿⠟⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⣀⣤⣴⣾⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡆⠀⠀⠀⠀⠁⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠙⢻⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠟⠙⣿⣿⣿⣷⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⢀⣤⣴⣾⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠟⠁⠀⠀⢹⣿⣿⣿⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⢀⣤⣾⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡿⠟⠋⠁⠀⠀⠀⠀⠈⣿⣿⡟⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⣴⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠿⠟⠛⢋⣩⡿⠿⠿⠟⠛⠋⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⣿⡟⠁⠀⠀⠀⠀⠀⠀⠀
⠀⢀⣾⣿⣿⣿⣿⣿⣿⣿⣿⣿⡿⠋⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠠⣄⣀⡀⠀⠀⠀⠀⠀⠐⠉⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⣾⣿⣿⣿⣿⣿⣿⣿⠻⣿⣿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠉⠻⢿⣶⣤⣄⡀⠀⠀⠀⠀⠀⠀⠀
⢰⣿⣿⣿⣿⣿⣿⣿⣿⡄⠙⢿⣄⠀⠀⠀⠀⠀⠀⠀⠀⠠⣤⣀⠀⠀⠀⠠⣄⣀⣀⡉⢻⣿⣿⣿⣶⣄⡀⠀⠀⠀⠀⠀⠀⠀
⠘⣿⣿⣿⣿⣿⣿⣿⣿⣿⣦⣄⣀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⣿⣿⣦⣤⣤⣶⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣷⣄⡀⠀⠀⠀⠀
⠀⢻⡟⠙⣿⣿⣿⣿⣿⣿⣿⣿⣿⠿⠛⠛⠋⠉⠀⠀⢀⣠⣾⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣦⡀⠀⠀
⠀⠀⠃⠀⢹⣿⣿⣿⣿⣿⣿⣿⣿⣿⣶⣶⣶⣶⣶⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡟⠁⠀⠀⠀⠀⠀⠈⠉⠻⢿⣿⣿⣿⣷⡄⠀
⠀⠀⠀⠀⢸⣿⣿⡟⠙⠿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡿⠿⠛⠛⣿⣿⣿⣿⣿⣧⣀⣀⡄⠀⠀⠀⠀⠀⠀⠈⣿⡿⣿⣿⣷⠀
⠀⠀⠀⠀⢸⣿⡿⠁⠀⠀⠀⠙⠻⠿⣟⠻⢿⣿⣿⣿⣷⣦⡀⠀⠈⠻⢿⣿⣿⣭⣉⡉⠀⠀⠀⠀⠀⠀⠀⠀⠘⠀⠸⣿⣿⡄
⠀⠀⠀⠀⣸⡟⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠉⠛⢿⣿⣿⣦⡀⠀⠀⠀⠉⠉⠉⠉⠉⠉⠁⠀⠀⠀⠀⠀⠀⠀⠀⣿⣿⠁
⠀⠀⠀⠠⠋⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠙⢿⣿⣆⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣿⡟⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠙⢿⡆⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢰⠟⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠁⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠰⡴⡖⡴⡖⡴⡄⢰⣀⣶⣰⡂⣶⢰⡆⣶⢰⣆⣰⣀⣆⡆⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
{ENDC}"""

SENSITIVE_REGEX = {
    "Google API Key": r"AIza[0-9A-Za-z-_]{35}",
    "Generic Secret": r"(?i)secret|password|api_key|token",
    "Email Leak": r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+"
}

EXTENSIONS = ['', '.php', '.json', '.env', '.bak']
COMMON_PATHS = ['admin', 'login', 'config', 'db', 'api/v1', 'api/v2', '.env', 'backup']
FOUND_ITEMS = []

def deep_file_analyzer(url, content):
    findings = []
    for name, pattern in SENSITIVE_REGEX.items():
        if re.search(pattern, content):
            findings.append(name)
    return findings

def sqli_scanner(target):
    print(f"{PURPLE}[*] Stage 3: Launching SQLi Scanner...{ENDC}")
    payloads = ["'", "' OR '1'='1"]
    sql_errors = ["sql syntax", "mysql_fetch", "ora-01756", "error in your sql syntax"]
    test_url = target if '?' in target else f"{target}?id=1"
    
    for payload in payloads:
        full_test_url = test_url.split('=')[0] + "=" + payload
        try:
            r = requests.get(full_test_url, timeout=5, verify=False)
            if any(error in r.text.lower() for error in sql_errors):
                msg = f"[SQLi VULNERABLE] {full_test_url}"
                print(f"{PURPLE}  [!] CRITICAL: {msg}{ENDC}")
                FOUND_ITEMS.append(msg)
            else:
                print(f"{PURPLE}  [-] Testing payload: {payload} (No SQL Error){ENDC}")
        except Exception as e:
            print(f"{PURPLE}  [!] Error testing SQLi: {e}{ENDC}")

def path_bruteforce(target):
    print(f"{PURPLE}[*] Stage 2: Deep Path Fuzzing...{ENDC}")
    scan_list = [f"{path}{ext}" for path in COMMON_PATHS for ext in EXTENSIONS]
    
    def check_url(p):
        full_url = urljoin(target, p)
        try:
            r = requests.get(full_url, headers={'User-Agent': 'Mozilla/5.0'}, timeout=5, verify=False, allow_redirects=False)
            if r.status_code == 200:
                analysis = deep_file_analyzer(full_url, r.text)
                res = f"[FOUND] {full_url} (Analysis: {analysis if analysis else 'Clean'})"
                print(f"{PURPLE}  [+] {res}{ENDC}")
                FOUND_ITEMS.append(res)
            elif r.status_code == 403:
                print(f"{PURPLE}  [!] Forbidden (403): {full_url}{ENDC}")
        except:
            pass

    with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
        executor.map(check_url, scan_list)

def js_scraper(target, html_content):
    print(f"{PURPLE}[*] Stage 1: Deep JS Scraping...{ENDC}")
    js_files = re.findall(r'src="([^"]+\.js)"', html_content)
    if not js_files:
        print(f"{PURPLE}  [-] No external JS files found.{ENDC}")
        return

    for js in js_files:
        full_url = urljoin(target, js)
        try:
            print(f"{PURPLE}  [~] Scraping: {full_url}{ENDC}")
            res = requests.get(full_url, timeout=5, verify=False)
            analysis = deep_file_analyzer(full_url, res.text)
            if analysis:
                msg = f"[JS LEAK] {full_url} | Secrets: {analysis}"
                print(f"{PURPLE}  [+] {msg}{ENDC}")
                FOUND_ITEMS.append(msg)
        except:
            pass

def advanced_scan(target):
    print(ASCII_ART)
    print(f"{PURPLE}{BOLD}--- WEB SCANNER STARTING ---{ENDC}")
    
    if not target.startswith('http'):
        target = 'http://' + target
    if not target.endswith('/'):
        target += '/'
        
    try:
        print(f"{PURPLE}[*] Connecting to: {target}{ENDC}")
        main_res = requests.get(target, timeout=10, verify=False)
        print(f"{PURPLE}[*] Connection Successful (Status: {main_res.status_code}){ENDC}")
        
        js_scraper(target, main_res.text)
        path_bruteforce(target)
        sqli_scanner(target)
        
        print(f"\n{PURPLE}{BOLD}" + "="*60)
        print("SCAN FINISHED - SUMMARY OF FINDINGS")
        print("="*60 + f"{ENDC}")
        
        if FOUND_ITEMS:
            for item in FOUND_ITEMS:
                print(f"{PURPLE}{item}{ENDC}")
        else:
            print(f"{PURPLE}No vulnerabilities or sensitive files were found.{ENDC}")
            
        print(f"\n{PURPLE}credits : swagrc7/asdqrc7{ENDC}")
    except Exception as e:
        print(f"{PURPLE}[!] Error: Could not connect to target. {e}{ENDC}")

if __name__ == "__main__":
    target = input(f"{PURPLE}Target URL (e.g. google.com): {ENDC}").strip()
    advanced_scan(target)
