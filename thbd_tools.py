import os
import sys
import requests
from colorama import init, Fore, Style

# Initialize colorama
init(autoreset=True)

# ---------- CONFIG ----------
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
DEFAULT_WORDLIST_FILENAME = "admin-finder.txt"
DEFAULT_WORDLIST_PATH = os.path.join(SCRIPT_DIR, DEFAULT_WORDLIST_FILENAME)

WORDLIST_DOWNLOAD_URL = "https://raw.githubusercontent.com/mrzico69/wordlists/main/admin-finder.txt"
TOOL_UPDATE_URL = "https://raw.githubusercontent.com/mrzico69/thbd_tools/refs/heads/main/thbd_tools.py"

custom_wordlist_path = ""

# ---------- AUTO DOWNLOAD WORDLIST ----------
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
        print(Fore.YELLOW + "[*] Default wordlist missing, downloading..." + Style.RESET_ALL)
        download_wordlist(WORDLIST_DOWNLOAD_URL, DEFAULT_WORDLIST_PATH)
    else:
        print(Fore.GREEN + "[✓] Default wordlist found." + Style.RESET_ALL)

def update_wordlist():
    print()
    print(Fore.CYAN + "[*] Updating default wordlist..." + Style.RESET_ALL)
    download_wordlist(WORDLIST_DOWNLOAD_URL, DEFAULT_WORDLIST_PATH)

# ---------- UPDATE TOOL FUNCTION ----------
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

    print(Fore.CYAN + "\n[✔] Scan finished." + Style.RESET_ALL)

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

# ---------- MAIN MENU ----------
def main_menu():
    while True:
        show_banner()
        print("Select a Tool:")
        print("1. Admin Finder")
        print("2. Update Tool (program)")
        print("3. Update Default Wordlist")
        print("0. Exit")

        choice = input("\nYour choice: ")

        if choice == "1":
            admin_finder_menu()
        elif choice == "2":
            update_tool()
        elif choice == "3":
            update_wordlist()
        elif choice == "0":
            print(Fore.CYAN + "👋 Bye! Stay sharp, Team THBD 💻⚔️" + Style.RESET_ALL)
            break
        else:
            print(Fore.RED + "❌ Invalid option." + Style.RESET_ALL)

# ---------- RUN ----------
if __name__ == "__main__":
    main_menu()
