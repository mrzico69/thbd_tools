import os
import sys
import requests
import random
import time
from urllib.parse import urlparse
from colorama import init, Fore, Style

# Initialize colorama for colorful terminal output
init(autoreset=True)

# =========================
# === CONFIG & CONSTANTS ===
# =========================

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))

# Wordlists URLs & paths for admin finder and dir brute force
DEFAULT_WORDLIST_FILENAME = "admin-finder.txt"
DEFAULT_WORDLIST_PATH = os.path.join(SCRIPT_DIR, DEFAULT_WORDLIST_FILENAME)
WORDLIST_DOWNLOAD_URL = (
    "https://raw.githubusercontent.com/mrzico69/wordlists/main/admin-finder.txt"
)

DIR_BRUTE_FILENAME = "dir-brute.txt"
DIR_BRUTE_PATH = os.path.join(SCRIPT_DIR, DIR_BRUTE_FILENAME)
DIR_BRUTE_URL = (
    "https://raw.githubusercontent.com/mrzico69/wordlists/main/dir-brute.txt"
)

# Default login brute force username/password lists
DEFAULT_USR_FILENAME = "default_usr.txt"
DEFAULT_PASS_FILENAME = "default_pass.txt"
DEFAULT_USR_PATH = os.path.join(SCRIPT_DIR, DEFAULT_USR_FILENAME)
DEFAULT_PASS_PATH = os.path.join(SCRIPT_DIR, DEFAULT_PASS_FILENAME)

DEFAULT_USR_URL = "https://raw.githubusercontent.com/mrzico69/wordlists/refs/heads/main/default_usr.txt"
DEFAULT_PASS_URL = "https://raw.githubusercontent.com/mrzico69/wordlists/refs/heads/main/default_pass.txt"

# Update URL for the tool itself
TOOL_UPDATE_URL = (
    "https://raw.githubusercontent.com/mrzico69/thbd_tools/main/thbd_tools.py"
)

# User agents list for randomizing requests (for WAF & login brute force)
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_4) AppleWebKit/605.1.15 "
    "(KHTML, like Gecko) Version/16.5 Safari/605.1.15",
    "Mozilla/5.0 (Linux; Android 12; SM-G991B) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/115.0.0.0 Mobile Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) Gecko/20100101 Firefox/115.0",
]

# Common CMS fingerprint patterns (headers, meta tags, HTML markers)
CMS_PATTERNS = {
    "WordPress": ["wp-content", "wp-includes", "xmlrpc.php", "wp-json"],
    "Joomla": ['content="Joomla!', "com_content", "index.php?option="],
    "Drupal": ["sites/default/files", "drupal.js", "drupal-settings-json"],
    "Laravel": ["laravel_session", "XSRF-TOKEN", "csrf-token"],
}

# Common WAF signatures (in status codes and response content)
WAF_SIGNATURES = {
    "Cloudflare": ["cloudflare", "cf-ray", "cf-cache-status"],
    "Sucuri": ["sucuri/cloudproxy", "Sucuri/Cloudproxy"],
    "Imperva": ["Incapsula", "Imperva"],
    "Akamai": ["AkamaiGHost", "Akamai"],
}

# ====================
# === UTILITIES ======
# ====================


def download_file(url, filepath):
    """Download a file from URL and save locally."""
    try:
        print(Fore.YELLOW + f"[*] Downloading: {url}" + Style.RESET_ALL)
        response = requests.get(url, timeout=20)
        response.raise_for_status()
        with open(filepath, "wb") as file:
            file.write(response.content)
        print(Fore.GREEN + f"[✓] Downloaded and saved to {filepath}" + Style.RESET_ALL)
    except Exception as e:
        print(Fore.RED + f"[✗] Download failed: {e}" + Style.RESET_ALL)


def ensure_wordlists():
    """Ensure default wordlists are present, download if missing."""
    if not os.path.exists(DEFAULT_WORDLIST_PATH):
        print(
            Fore.YELLOW
            + "[*] Admin finder wordlist missing, downloading..."
            + Style.RESET_ALL
        )
        download_file(WORDLIST_DOWNLOAD_URL, DEFAULT_WORDLIST_PATH)
    else:
        print(Fore.GREEN + "[✓] Admin finder wordlist found." + Style.RESET_ALL)

    if not os.path.exists(DIR_BRUTE_PATH):
        print(
            Fore.YELLOW
            + "[*] Dir brute force wordlist missing, downloading..."
            + Style.RESET_ALL
        )
        download_file(DIR_BRUTE_URL, DIR_BRUTE_PATH)
    else:
        print(Fore.GREEN + "[✓] Dir brute force wordlist found." + Style.RESET_ALL)


def ensure_login_wordlists():
    """Ensure default login brute force username and password lists are present."""
    if not os.path.exists(DEFAULT_USR_PATH):
        print(
            Fore.YELLOW
            + "[*] Default username list missing, downloading..."
            + Style.RESET_ALL
        )
        download_file(DEFAULT_USR_URL, DEFAULT_USR_PATH)
    else:
        print(Fore.GREEN + "[✓] Default username list found." + Style.RESET_ALL)

    if not os.path.exists(DEFAULT_PASS_PATH):
        print(
            Fore.YELLOW
            + "[*] Default password list missing, downloading..."
            + Style.RESET_ALL
        )
        download_file(DEFAULT_PASS_URL, DEFAULT_PASS_PATH)
    else:
        print(Fore.GREEN + "[✓] Default password list found." + Style.RESET_ALL)


def get_random_user_agent():
    """Return a random User-Agent string from the list."""
    return random.choice(USER_AGENTS)


def print_banner():
    """Show tool banner."""
    banner = r"""
█████████╗██╗  ██╗██████╗ ██████╗ 
╚══██╔══╝██║  ██║██╔══██╗██╔══██╗
   ██║   ███████║██████╔╝██║  ██║
   ██║   ██╔══██║██╔══██╗██║  ██║
   ██║   ██║  ██║██████╔╝██████╔╝
   ╚═╝   ╚═╝  ╚═╝╚═════╝ ╚═════╝  
"""
    print(
        Fore.CYAN
        + Style.BRIGHT
        + banner
        + Fore.YELLOW
        + "        TOOLS by Team THBD ⚡\n"
        + Style.RESET_ALL
    )


# =====================
# === FEATURE 1: CMS Detector ===
# =====================


def cms_detector(url):
    """
    Detect CMS by checking common CMS patterns in HTML and headers.
    """
    print(Fore.MAGENTA + f"\n[🔍] Running CMS Detector on {url}\n" + Style.RESET_ALL)
    if not url.startswith("http"):
        url = "http://" + url

    try:
        headers = {"User-Agent": get_random_user_agent()}
        response = requests.get(url, headers=headers, timeout=10)
        content = response.text.lower()
        detected = []

        # Check headers for clues
        for cms_name, patterns in CMS_PATTERNS.items():
            for pattern in patterns:
                if (
                    pattern.lower() in content
                    or pattern.lower() in str(response.headers).lower()
                ):
                    detected.append(cms_name)
                    break  # If one pattern found, no need to check others for this CMS

        if detected:
            print(
                Fore.GREEN
                + f"[✓] Possible CMS detected: {', '.join(set(detected))}"
                + Style.RESET_ALL
            )
        else:
            print(
                Fore.YELLOW
                + "[!] No CMS detected or CMS is custom/unknown."
                + Style.RESET_ALL
            )

    except Exception as e:
        print(Fore.RED + f"[✗] Error while detecting CMS: {e}" + Style.RESET_ALL)


# ===============================
# === FEATURE 2: Wayback URL Extractor ===
# ===============================


def wayback_url_extractor(domain):
    """
    Extract archived URLs for a domain from web.archive.org
    """
    print(
        Fore.MAGENTA
        + f"\n[🌐] Extracting URLs from Wayback Machine for {domain}\n"
        + Style.RESET_ALL
    )
    if "http" in domain:
        domain = urlparse(domain).netloc

    api_url = f"http://web.archive.org/cdx/search/cdx?url={domain}/*&output=json&fl=original&collapse=urlkey"
    try:
        response = requests.get(api_url, timeout=15)
        response.raise_for_status()
        urls = response.json()
        if len(urls) < 2:
            print(Fore.YELLOW + "[!] No archived URLs found." + Style.RESET_ALL)
            return

        print(
            Fore.GREEN + f"[✓] Found {len(urls) - 1} archived URLs:\n" + Style.RESET_ALL
        )
        for u in urls[1:]:  # skip header
            print(u[0])
    except Exception as e:
        print(Fore.RED + f"[✗] Failed to extract Wayback URLs: {e}" + Style.RESET_ALL)


# =====================
# === FEATURE 3: WAF Detector ===
# =====================


def waf_detector(url):
    """
    Detect WAF by checking response headers and content for known WAF signatures.
    """
    print(Fore.MAGENTA + f"\n[🛡️] Running WAF Detector on {url}\n" + Style.RESET_ALL)
    if not url.startswith("http"):
        url = "http://" + url

    headers = {"User-Agent": get_random_user_agent()}

    try:
        response = requests.get(url, headers=headers, timeout=10)
        content_lower = response.text.lower()
        headers_lower = str(response.headers).lower()
        detected_wafs = []

        for waf_name, signatures in WAF_SIGNATURES.items():
            for sig in signatures:
                if sig.lower() in content_lower or sig.lower() in headers_lower:
                    detected_wafs.append(waf_name)
                    break

        if detected_wafs:
            print(
                Fore.GREEN
                + f"[✓] WAF detected: {', '.join(set(detected_wafs))}"
                + Style.RESET_ALL
            )
        else:
            print(Fore.YELLOW + "[!] No WAF detected or unknown WAF." + Style.RESET_ALL)

    except Exception as e:
        print(Fore.RED + f"[✗] WAF detection failed: {e}" + Style.RESET_ALL)


# =========================
# === FEATURE 4: Login Page Brute Force ===
# =========================


def login_bruteforce():
    """
    Brute force login page using username and password wordlists.
    Supports default (auto download) and custom user/pass lists.
    """
    print(Fore.MAGENTA + "\n[🔐] Login Page Brute Force\n" + Style.RESET_ALL)
    login_url = input("Enter login form URL: ").strip()
    username_field = input("Enter the username form field name: ").strip()
    password_field = input("Enter the password form field name: ").strip()
    success_indicator = input(
        "Enter a keyword/text that appears on login success page (e.g. 'dashboard'): "
    ).strip()

    # Choose default or custom wordlists
    while True:
        print("\nChoose Wordlist Option:")
        print("1. Use Default Wordlists (auto-download if missing)")
        print("2. Use Custom Wordlists")
        choice = input("Your choice: ").strip()

        if choice == "1":
            ensure_login_wordlists()
            if not (
                os.path.exists(DEFAULT_USR_PATH) and os.path.exists(DEFAULT_PASS_PATH)
            ):
                print(
                    Fore.RED
                    + "❌ Default login wordlists missing or failed to download."
                    + Style.RESET_ALL
                )
                return
            username_list_path = DEFAULT_USR_PATH
            password_list_path = DEFAULT_PASS_PATH
            break
        elif choice == "2":
            username_list_path = input("Enter path to username list file: ").strip()
            password_list_path = input("Enter path to password list file: ").strip()
            if not os.path.exists(username_list_path):
                print(Fore.RED + "❌ Username list file not found." + Style.RESET_ALL)
                continue
            if not os.path.exists(password_list_path):
                print(Fore.RED + "❌ Password list file not found." + Style.RESET_ALL)
                continue
            break
        else:
            print(
                Fore.RED + "❌ Invalid option. Please choose 1 or 2." + Style.RESET_ALL
            )

    # Load username and password lists
    with open(username_list_path, "r") as f:
        usernames = [line.strip() for line in f if line.strip()]

    with open(password_list_path, "r") as f:
        passwords = [line.strip() for line in f if line.strip()]

    print(Fore.YELLOW + f"[*] Starting brute force on {login_url}..." + Style.RESET_ALL)

    session = requests.Session()

    for username in usernames:
        for password in passwords:
            headers = {"User-Agent": get_random_user_agent()}
            data = {username_field: username, password_field: password}

            try:
                response = session.post(
                    login_url, data=data, headers=headers, timeout=10
                )
                if success_indicator.lower() in response.text.lower():
                    print(
                        Fore.GREEN
                        + f"[✓] Login successful with {username}:{password}"
                        + Style.RESET_ALL
                    )
                    return
                else:
                    print(
                        Fore.BLUE
                        + f"Trying {username}:{password} - Failed"
                        + Style.RESET_ALL
                    )
                time.sleep(0.5)
            except Exception as e:
                print(Fore.RED + f"[✗] Request error: {e}" + Style.RESET_ALL)
                return

    print(
        Fore.YELLOW
        + "[!] Brute force completed. No valid credentials found."
        + Style.RESET_ALL
    )


# =====================
# === YOU CAN ADD YOUR EXISTING ADMIN FINDER, DIR BRUTE FORCE, COMBO, UPDATE FUNCTIONS HERE ===
# (For brevity not repeated here; add your current code for those features)
# =====================

# === MAIN MENU ===


def main_menu():
    while True:
        print_banner()
        print("Select a Tool:")
        print("1. Admin Finder")
        print("2. Dir Brute Force")
        print("3. Combo Attack (Admin + Dir Brute)")
        print("4. CMS Detector")
        print("5. Wayback URL Extractor")
        print("6. WAF Detector")
        print("7. Login Page Brute Force")
        print("8. Update Tool (program)")
        print("9. Update Default Wordlists")
        print("0. Exit")

        choice = input("\nYour choice: ").strip()

        if choice == "1":
            admin_finder_menu()  # Your existing function
        elif choice == "2":
            dir_brute_menu()  # Your existing function
        elif choice == "3":
            combo_attack()  # Your existing function
        elif choice == "4":
            target = input("Enter target URL (e.g. example.com): ").strip()
            cms_detector(target)
        elif choice == "5":
            domain = input(
                "Enter domain for Wayback URL extraction (e.g. example.com): "
            ).strip()
            wayback_url_extractor(domain)
        elif choice == "6":
            target = input("Enter target URL (e.g. example.com): ").strip()
            waf_detector(target)
        elif choice == "7":
            login_bruteforce()
        elif choice == "8":
            update_tool()  # Your existing function
        elif choice == "9":
            update_wordlist()  # Your existing function
        elif choice == "0":
            print(Fore.CYAN + "👋 Bye! Stay sharp, Team THBD 💻⚔️" + Style.RESET_ALL)
            break
        else:
            print(Fore.RED + "❌ Invalid option." + Style.RESET_ALL)


# =====================
# === ENTRY POINT ===
# =====================

if __name__ == "__main__":
    main_menu()
