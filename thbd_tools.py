import os
import sys
import requests
from colorama import init, Fore, Style

# Initialize colorama
init(autoreset=True)

# ---------- CONFIG ----------
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))

# Wordlists
DEFAULT_WORDLIST_FILENAME = "admin-finder.txt"
DEFAULT_WORDLIST_PATH = os.path.join(SCRIPT_DIR, DEFAULT_WORDLIST_FILENAME)
WORDLIST_DOWNLOAD_URL = "https://raw.githubusercontent.com/mrzico69/wordlists/refs/heads/main/admin-finder.txt"

DIR_BRUTE_FILENAME = "dir-brute.txt"
DIR_BRUTE_PATH = os.path.join(SCRIPT_DIR, DIR_BRUTE_FILENAME)
DIR_BRUTE_URL = "https://raw.githubusercontent.com/mrzico69/wordlists/refs/heads/main/dir-brute.txt"

# Update URLs
TOOL_UPDATE_URL = "https://raw.githubusercontent.com/mrzico69/thbd_tools/refs/heads/main/thbd_tools.py"

# Dirsearch path
DIRSEARCH_PATH = os.path.join(SCRIPT_DIR, "dirsearch", "dirsearch.py")

custom_wordlist_path = ""

# ---------- UTILITIES ----------

def download_wordlist(url, filepath):
    try:
        print(Fore.YELLOW + "[*] Downloading..." + Style.RESET_ALL)
        r = requests.get(url, timeout=15)
        r.raise_for_status()
        with open(filepath, "wb") as f:
            f.write(r.content)
        print(Fore.GREEN + "[✓] Download successful." + Style.RESET_ALL)
    except Exception as e:
        print(Fore.RED + f"[✗] Download failed: {e}" + Style.RESET_ALL)

def ensure_wordlist():
    if not os.path.exists(DEFAULT_WORDLIST_PATH):
        print(Fore.YELLOW + "[*] Default admin wordlist missing, downloading..." + Style.RESET_ALL)
        download_wordlist(WORDLIST_DOWNLOAD_URL, DEFAULT_WORDLIST_PATH)
    else:
        print(Fore.GREEN + "[✓] Default admin wordlist found." + Style.RESET_ALL)

def ensure_dir_brute():
    if not os.path.exists(DIR_BRUTE_PATH):
        print(Fore.YELLOW + "[*] Default dir-brute.txt missing, downloading..." + Style.RESET_ALL)
        download_wordlist(DIR_BRUTE_URL, DIR_BRUTE_PATH)
    else:
        print(Fore.GREEN + "[✓] Default dir-brute.txt found." + Style.RESET_ALL)

def update_wordlist():
    print()
    print(Fore.CYAN + "[*] Updating default admin wordlist..." + Style.RESET_ALL)
    download_wordlist(WORDLIST_DOWNLOAD_URL, DEFAULT_WORDLIST_PATH)
    print(Fore.CYAN + "[*] Updating default dir-brute wordlist..." + Style.RESET_ALL)
    download_wordlist(DIR_BRUTE_URL, DIR_BRUTE_PATH)

def update_tool():
    script_file = os.path.abspath(__file__)
    try:
        print(Fore.YELLOW + "[*] Downloading latest version of the tool..." + Style.RESET_ALL)
        r = requests.get(TOOL_UPDATE_URL, timeout=15)
        r.raise_for_status()
        with open(script_file, "wb") as f:
            f.write(r.content)
        print(Fore.GREEN + "[✓] Update successful! Please restart the tool." + Style.RESET_ALL)
        sys.exit(0)
    except Exception as e:
        print(Fore.RED + f"[✗] Update failed: {e}" + Style.RESET_ALL)

# ---------- BANNER ----------
def show_banner():
    print(Fore.CYAN + Style.BRIGHT + r"""
          
█████████╗██╗  ██╗██████╗ ██████╗ 
╚══██╔══╝██║  ██║██╔══██╗██╔══██╗
   ██║   ███████║██████╔╝██║  ██║
   ██║   ██╔══██║██╔══██╗██║  ██║
   ██║   ██║  ██║██████╔╝██████╔╝
   ╚═╝   ╚═╝  ╚═╝╚═════╝ ╚═════╝  
""" + Fore.YELLOW + Style.BRIGHT + "        TOOLS by Team THBD ⚡\n" + Style.RESET_ALL)

# ---------- ADMIN FINDER ----------
def admin_finder(target_url, wordlist_path):
    print(f"\n{Fore.MAGENTA}[🔎] Scanning {target_url} for admin panels...\n{Style.RESET_ALL}")
    if not target_url.startswith("http"):
        target_url = "http://" + target_url

    try:
        with open(wordlist_path, "r") as file:
            paths = file.read().splitlines()
    except FileNotFoundError:
        print(Fore.RED + "❌ Wordlist not found!" + Style.RESET_ALL)
        return

    total = len(paths)
    for i, path in enumerate(paths, start=1):
        full_url = target_url.rstrip("/") + "/" + path
        print(Fore.BLUE + f"[{i}/{total}] Trying", end='\r')

        try:
            response = requests.get(full_url, timeout=5)
            if response.status_code == 200:
                print(Fore.GREEN + f"\n[✓] Found: {full_url}" + Style.RESET_ALL)
        except requests.RequestException:
            pass

    print(Fore.CYAN + "\n[✔] Admin scan finished." + Style.RESET_ALL)

# ---------- DIR BRUTE FORCE WITH STATUS ----------
def dir_brute_force(target_url):
    ensure_dir_brute()
    if not target_url.startswith("http"):
        target_url = "http://" + target_url

    try:
        with open(DIR_BRUTE_PATH, "r") as f:
            paths = f.read().splitlines()
    except:
        print(Fore.RED + "❌ Could not load dir-brute.txt" + Style.RESET_ALL)
        return

    print(f"\n{Fore.MAGENTA}[🔎] Brute-forcing directories on {target_url}...\n{Style.RESET_ALL}")
    for path in paths:
        full_url = f"{target_url.rstrip('/')}/{path.lstrip('/')}"
        try:
            response = requests.get(full_url, timeout=5)
            code = response.status_code
            color = Fore.GREEN if code == 200 else Fore.YELLOW if code == 403 else Fore.RED
            print(f"[{color}{code}{Style.RESET_ALL}] {full_url}")
        except:
            print(f"[---] {full_url} - Timed out or error")
    print(Fore.CYAN + "\n[✔] Dir brute force finished." + Style.RESET_ALL)

# ---------- RUN DIRSEARCH AUTOMATE ----------
def run_dirsearch(target_url):
    if not os.path.exists(DIRSEARCH_PATH):
        print(Fore.RED + "[✗] dirsearch not found in current directory. Clone it first!" + Style.RESET_ALL)
        print(Fore.YELLOW + "    git clone https://github.com/maurosoria/dirsearch" + Style.RESET_ALL)
        return
    ensure_dir_brute()
    print(Fore.YELLOW + "[*] Launching Dirsearch..." + Style.RESET_ALL)
    cmd = f'python3 "{DIRSEARCH_PATH}" -u "{target_url}" -e * -w "{DIR_BRUTE_PATH}"'
    os.system(cmd)

# ---------- OWN WORDLIST MENU ----------
def own_wordlist_menu(target_url):
    global custom_wordlist_path
    while True:
        print("\n[ Own Wordlist Menu ]")
        print("1. Attack")
        print("2. Change Wordlist")
        print("0. Back")
        choice = input("Choose: ")

        if choice == "1":
            if custom_wordlist_path == "":
                print(Fore.RED + "❌ No wordlist set. Choose option 2 first." + Style.RESET_ALL)
            else:
                admin_finder(target_url, custom_wordlist_path)
        elif choice == "2":
            path = input("Enter full path to your wordlist: ")
            if os.path.exists(path):
                custom_wordlist_path = path
                print(Fore.GREEN + "[✓] Wordlist set." + Style.RESET_ALL)
            else:
                print(Fore.RED + "❌ File not found." + Style.RESET_ALL)
        elif choice == "0":
            break
        else:
            print(Fore.RED + "❌ Invalid option." + Style.RESET_ALL)

# ---------- ADMIN FINDER MENU ----------
def admin_finder_menu():
    while True:
        print("\n[ Admin Finder ]")
        print("1. Default Wordlist (admin-finder.txt)")
        print("2. Own Wordlist")
        print("0. Back")

        choice = input("Choose an option: ")

        if choice == "1":
            target_url = input("Enter target website (e.g. example.com): ")
            ensure_wordlist()
            admin_finder(target_url, DEFAULT_WORDLIST_PATH)

        elif choice == "2":
            target_url = input("Enter target website (e.g. example.com): ")
            own_wordlist_menu(target_url)

        elif choice == "0":
            return
        else:
            print(Fore.RED + "❌ Invalid option." + Style.RESET_ALL)

# ---------- DIR BRUTE FORCE MENU ----------
def dir_brute_menu():
    while True:
        print("\n[ Dir Brute Force ]")
        print("1. Dir Brute Force (Default Wordlist)")
        print("2. Dirsearch Automate")
        print("0. Back")
        choice = input("Choose an option: ")

        if choice == "1":
            target_url = input("Enter target website (e.g. example.com): ")
            dir_brute_force(target_url)

        elif choice == "2":
            target_url = input("Enter target website (e.g. example.com): ")
            run_dirsearch(target_url)

        elif choice == "0":
            break
        else:
            print(Fore.RED + "❌ Invalid option." + Style.RESET_ALL)

# ---------- COMBO ATTACK (ADMIN + DIR) ----------
def combo_attack():
    target_url = input("Enter target website (e.g. example.com): ")
    print(Fore.CYAN + "\n[Starting Admin Finder Scan...]\n" + Style.RESET_ALL)
    ensure_wordlist()
    admin_finder(target_url, DEFAULT_WORDLIST_PATH)

    print(Fore.CYAN + "\n[Starting Dir Brute Force Scan...]\n" + Style.RESET_ALL)
    ensure_dir_brute()
    dir_brute_force(target_url)

# ---------- MAIN MENU ----------
def main_menu():
    while True:
        show_banner()
        print("Select a Tool:")
        print("1. Admin Finder")
        print("2. Dir Brute Force")
        print("3. Combo Attack (Admin + Dir Brute)")
        print("4. Update Tool (program)")
        print("5. Update Default Wordlists")
        print("0. Exit")

        choice = input("\nYour choice: ")

        if choice == "1":
            admin_finder_menu()
        elif choice == "2":
            dir_brute_menu()
        elif choice == "3":
            combo_attack()
        elif choice == "4":
            update_tool()
        elif choice == "5":
            update_wordlist()
        elif choice == "0":
            print(Fore.CYAN + "👋 Bye! Stay sharp, Team THBD 💻⚔️" + Style.RESET_ALL)
            break
        else:
            print(Fore.RED + "❌ Invalid option." + Style.RESET_ALL)

# ---------- RUN ----------
if __name__ == "__main__":
    main_menu()
