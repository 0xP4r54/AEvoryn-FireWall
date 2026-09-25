#!/usr/bin/env python3

import subprocess
import os
import datetime
import shutil
import sys
import ipaddress
import platform
from time import sleep


VERSION = "1.0.0"
TABLE = "AEvoryn"
CHAIN = "input"
CONFIG_FILE = "/etc/aevoryn.nft"
LOG_FILE = "/var/log/aevoryn.log"


def printLow(text):
    for char in text:
        print(char, end="", flush=True)
        sleep(0.01)


def startup():
    os.system("clear")
    r = "\033[1;31m"
    g = "\033[32;1m"
    y = "\033[1;33m"
    w = "\033[1;37m"
    reset = "\033[0m"
    banner = (
        " ██████╗ ██╗  ██╗██████╗ ██╗  ██╗██████╗ ███████╗██╗  ██╗\n"
        "██╔═████╗╚██╗██╔╝██╔══██╗██║  ██║██╔══██╗██╔════╝██║  ██║\n"
        "██║██╔██║ ╚███╔╝ ██████╔╝███████║██████╔╝███████╗███████║\n"
        "████╔╝██║ ██╔██╗ ██╔═══╝ ╚════██║██╔══██╗╚════██║╚════██║\n"
        "╚██████╔╝██╔╝ ██╗██║          ██║██║  ██║███████║     ██║\n"
        " ╚═════╝ ╚═╝  ╚═╝╚═╝          ╚═╝╚═╝  ╚═╝╚══════╝     ╚═╝\n"
    )
    printLow(f"{r}{banner}{reset}")
    input("\nPress Enter to continue...")
    os.system("clear")
    ascii_banner = r"""                                         
     ▄▄▄▄▄▄▄▄                            
   ▄█▀▀██▀▀▀                             
   ██  ██                ▄          ▄    
   ██▀▀████ ▀█▄ ██▀▄███▄ ████▄██ ██ ████▄
 ▄ ██  ██    ██▄██ ██ ██ ██   ██▄██ ██ ██
 ▀██▀  ▀█████ ▀█▀ ▄▀███▀▄█▀  ▄▄▀██▀▄██ ▀█
                                ██       
                              ▀▀▀        """
    printLow(f"{r}{ascii_banner}{reset}\n\n")
    printLow(
        f"{g} Ævoryn firewall\n\n"
        f"{y}Info:\n"
        f"    {g}[+] {y}GitHub account: {w}@0xp4r54\n"
        f"    {g}[+] {y}Version: {w}{VERSION}\n"
        f"    {y}system:\n"
        f"    {g}[+] {y}Platform: {w}{platform.system()}\n"
        f"    {g}[+] {y}Node: {w}{platform.node()}\n"
        f"    {g}[+] {y}Release: {w}{platform.release()}\n{reset}\n"
    )
    input("Press Enter to open Ævoryn...")
    os.system("clear")


def run(command, check=True):
    try:
        result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=check)
        return result.stdout.strip()
    except subprocess.CalledProcessError as e:
        if e.stderr:
            print("\n[!] Command failed:")
            print(" ".join(command))
            print(e.stderr.strip())
        return ""


def log(message):
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    line = f"[{timestamp}] {message}"
    print(line)
    try:
        with open(LOG_FILE, "a") as f:
            f.write(line + "\n")
    except PermissionError:
        pass


def pause():
    input("\nPress Enter to continue...")


def root_check():
    if os.geteuid() != 0:
        print("\n[!] This program must run as root.\n\nRun:\n    sudo python3 aevoryn_firewall.py\n")
        sys.exit(1)


def dependency_check():
    if shutil.which("nft") is None:
        print("\n[!] nftables is not installed.\n\nInstall it with:\n    sudo apt install nftables\n")
        sys.exit(1)
    for command in ("ip", "ss"):
        if shutil.which(command) is None:
            print(f"[!] Required command not found: {command}")
            sys.exit(1)


def valid_port(value):
    return value.isdigit() and 1 <= int(value) <= 65535


def valid_ipv4(value):
    try:
        return ipaddress.ip_address(value).version == 4
    except ValueError:
        return False


def initialize_firewall():
    print("\n[+] Initializing Ævoryn firewall...")

    # Create table
    result = run(
        ["nft", "add", "table", "inet", TABLE],
        check=False
    )

    # Create input chain
    run(
        [
            "nft", "add", "chain", "inet", TABLE, CHAIN,
            "{",
            "type", "filter",
            "hook", "input",
            "priority", "-100",
            "policy", "accept",
            "}"
        ],
        check=False
    )

    # Create sets
    for name, type_name in (
        ("blocked_ipv4", "ipv4_addr"),
        ("blocked_tcp", "inet_service"),
        ("blocked_udp", "inet_service")
    ):
        run(
            [
                "nft", "add", "set",
                "inet", TABLE, name,
                "{", "type", type_name, "}"
            ],
            check=False
        )

    # Add firewall rules
    current = run(
        ["nft", "list", "table", "inet", TABLE],
        check=False
    )

    rules = [
        [
            "ip", "saddr", "@blocked_ipv4",
            "log", "prefix", "AEVORYN_BLOCK_IP: ", "drop"
        ],
        [
            "tcp", "dport", "@blocked_tcp",
            "log", "prefix", "AEVORYN_BLOCK_TCP: ", "drop"
        ],
        [
            "udp", "dport", "@blocked_udp",
            "log", "prefix", "AEVORYN_BLOCK_UDP: ", "drop"
        ]
    ]

    for rule in rules:
        rule_text = " ".join(rule)

        if rule_text not in current:
            run(
                ["nft", "add", "rule", "inet", TABLE, CHAIN] + rule,
                check=False
            )

    # Verify actual firewall state
    status = run(
        ["nft", "list", "table", "inet", TABLE],
        check=False
    )

    if status:
        print("[+] Ævoryn firewall initialized successfully.")
        return True

    print("[!] Ævoryn firewall initialization failed.")
    return False


def firewall_status():
    print("\n========== ÆVORYN STATUS ==========\n")

    result = run(
        ["nft", "list", "table", "inet", TABLE],
        check=False
    )

    if result:
        print("[+] Ævoryn Firewall: ACTIVE")
        print(f"[+] Table: {TABLE}")
        print(f"[+] Chain: {CHAIN}")
        print("\n" + result)
    else:
        print("[!] Ævoryn Firewall: NOT ACTIVE")
        print("[!] The Ævoryn nftables table was not found.")

    pause()


def system_scan():
    print("\n========== SYSTEM SCAN ==========\n")
    print("[+] Hostname:")
    print(run(["hostname"]))
    print("\n[+] Kernel:")
    print(run(["uname", "-a"]))
    print("\n[+] Network interfaces:")
    print(run(["ip", "-br", "addr"]))
    print("\n[+] Routing table:")
    print(run(["ip", "route"]))
    print("\n[+] DNS:")
    print(run(["bash", "-c", "cat /etc/resolv.conf"], check=False))
    pause()


def listening_ports():
    print("\n========== LISTENING PORTS ==========\n")
    print(run(["ss", "-tulpn"]))
    pause()


def active_connections():
    print("\n========== ACTIVE CONNECTIONS ==========\n")
    print(run(["ss", "-tunap"]))
    pause()


def show_rules():
    print("\n========== ÆVORYN FIREWALL RULES ==========\n")
    result = run(["nft", "list", "table", "inet", TABLE], check=False)
    print(result if result else "[!] No rules found.")
    pause()


def block_ip():
    ip = input("\nEnter IPv4 address to BLOCK: ").strip()
    if not valid_ipv4(ip):
        print("[!] Invalid IPv4 address.")
        pause(); return
    run(["nft", "add", "element", "inet", TABLE, "blocked_ipv4", "{", ip, "}"], check=False)
    log(f"BLOCKED IPv4: {ip}")
    print(f"\n[+] {ip} is now BLOCKED.")
    pause()


def unblock_ip():
    ip = input("\nEnter IPv4 address to UNBLOCK: ").strip()
    if not valid_ipv4(ip):
        print("[!] Invalid IPv4 address.")
        pause(); return
    run(["nft", "delete", "element", "inet", TABLE, "blocked_ipv4", "{", ip, "}"], check=False)
    log(f"UNBLOCKED IPv4: {ip}")
    print(f"\n[+] {ip} is now UNBLOCKED.")
    pause()


def block_tcp():
    port = input("\nTCP port to BLOCK: ").strip()
    if not valid_port(port):
        print("[!] Invalid port. Use 1-65535.")
        pause(); return
    run(["nft", "add", "element", "inet", TABLE, "blocked_tcp", "{", port, "}"], check=False)
    log(f"BLOCKED TCP PORT: {port}")
    print(f"\n[+] TCP/{port} blocked.")
    pause()


def unblock_tcp():
    port = input("\nTCP port to UNBLOCK: ").strip()
    if not valid_port(port):
        print("[!] Invalid port. Use 1-65535.")
        pause(); return
    run(["nft", "delete", "element", "inet", TABLE, "blocked_tcp", "{", port, "}"], check=False)
    log(f"UNBLOCKED TCP PORT: {port}")
    print(f"\n[+] TCP/{port} unblocked.")
    pause()


def block_udp():
    port = input("\nUDP port to BLOCK: ").strip()
    if not valid_port(port):
        print("[!] Invalid port. Use 1-65535.")
        pause(); return
    run(["nft", "add", "element", "inet", TABLE, "blocked_udp", "{", port, "}"], check=False)
    log(f"BLOCKED UDP PORT: {port}")
    print(f"\n[+] UDP/{port} blocked.")
    pause()


def unblock_udp():
    port = input("\nUDP port to UNBLOCK: ").strip()
    if not valid_port(port):
        print("[!] Invalid port. Use 1-65535.")
        pause(); return
    run(["nft", "delete", "element", "inet", TABLE, "blocked_udp", "{", port, "}"], check=False)
    log(f"UNBLOCKED UDP PORT: {port}")
    print(f"\n[+] UDP/{port} unblocked.")
    pause()


def save_rules():
    print("\n[+] Saving Ævoryn configuration...")
    result = run(["nft", "list", "table", "inet", TABLE], check=False)
    if not result:
        print("[!] Could not read Ævoryn table.")
        pause(); return
    try:
        with open(CONFIG_FILE, "w") as f:
            f.write(result + "\n")
        log("Firewall rules saved.")
        print(f"[+] Saved to: {CONFIG_FILE}")
    except OSError as e:
        print(f"[!] Error: {e}")
    pause()


def load_rules():
    if not os.path.exists(CONFIG_FILE):
        print("[!] No saved configuration found.")
        pause(); return
    print("\n[+] Loading Ævoryn configuration...")
    run(["nft", "-f", CONFIG_FILE], check=False)
    log("Firewall rules loaded.")
    print("[+] Configuration loaded.")
    pause()


def reset_firewall():
    print("""
WARNING!

This will DELETE the Ævoryn table
and all rules created by this program.

Other nftables tables are not intentionally changed.

Type RESET to continue.
""")
    if input("> ").strip() != "RESET":
        print("[!] Cancelled.")
        pause(); return
    run(["nft", "delete", "table", "inet", TABLE], check=False)
    initialize_firewall()
    log("Ævoryn reset.")
    print("\n[+] Ævoryn reset successfully.")
    pause()



        


# ANSI colors
RESET  = "\033[0m"
GREEN  = "\033[92m"
CYAN   = "\033[96m"
RED    = "\033[91m"
YELLOW = "\033[93m"
WHITE  = "\033[97m"
DIM    = "\033[2m"

def menu():
    while True:
        os.system("clear")

        print(f"""
{GREEN}╔════════════════════════════════════════════╗
║                  ÆVORYN                    ║
║          Linux nftables Manager            ║
╚════════════════════════════════════════════╝{RESET}

 {CYAN}[1]{RESET}  Firewall Status
 {CYAN}[2]{RESET}  System Scan
 {CYAN}[3]{RESET}  Listening Ports
 {CYAN}[4]{RESET}  Active Connections
 {CYAN}[5]{RESET}  Show Firewall Rules

 {GREEN}─────────── IP CONTROL ───────────{RESET}

 {CYAN}[6]{RESET}  Block IP
 {CYAN}[7]{RESET}  Unblock IP

 {GREEN}─────────── TCP CONTROL ──────────{RESET}

 {CYAN}[8]{RESET}  Block TCP Port
 {CYAN}[9]{RESET}  Unblock TCP Port

 {GREEN}─────────── UDP CONTROL ──────────{RESET}

 {CYAN}[10]{RESET} Block UDP Port
 {CYAN}[11]{RESET} Unblock UDP Port

 {GREEN}─────────── CONFIGURATION ────────{RESET}

 {CYAN}[12]{RESET} Save Rules
 {CYAN}[13]{RESET} Load Rules
 {RED}[14]{RESET} Reset Firewall

 {RED}[0]{RESET}  Exit

{DIM}════════════════════════════════════════════{RESET}
""")

        choice = input(f"{GREEN}ÆVORYN@root{RESET}:{CYAN}~{RESET}$ ")


        choice = input("Select: ").strip()
        actions = {"1": firewall_status, "2": system_scan, "3": listening_ports, "4": active_connections, "5": show_rules, "6": block_ip, "7": unblock_ip, "8": block_tcp, "9": unblock_tcp, "10": block_udp, "11": unblock_udp, "12": save_rules, "13": load_rules, "14": reset_firewall}
        if choice == "0":
            print("\n[+] Exiting Ævoryn...")
            break
        action = actions.get(choice)
        if action:
            action()
        else:
            print("\n[!] Invalid option.")
            pause()


if __name__ == "__main__":
    startup()
    root_check()
    dependency_check()
    initialize_firewall()
    menu()
