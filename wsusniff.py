#!/usr/bin/env python3

import argparse
import re
import signal
import sys
from datetime import datetime
from scapy.all import sniff, TCP, Raw, IP

# ====================== CONFIG ======================

LOGFILE = "wsusniff.log"
WSUS_ENDPOINTS = [
    "ClientWebService/Client.asmx",
    "ClientWebService/SimpleAuth.asmx",
    "simpleauthwebservice/simpleauth.asmx",
    "ReportingWebService/ReportingWebService.asmx",
    "ApiRemoting30/WebService.asmx",
    "get-config.xml",
    "get-cookie.xml",
    "get-authorization-cookie.xml",
    "get-extended-update-info.xml",
    "report-event-batch.xml",
    "register-computer.xml",
    "sync-updates.xml",
    "internal-error.xml"
]

# ====================== COLORS ======================

GREEN = "\033[92m"
CYAN = "\033[96m"
YELLOW = "\033[93m"
RED = "\033[91m"
MAGENTA = "\033[95m"
BOLD = "\033[1m"
RESET = "\033[0m"

# ====================== STATE =======================

wsus_servers = set()
wsus_clients = set()

# ====================== LOGGING =====================

def log(entry):
    print(entry)
    with open(LOGFILE, "a") as f:
        f.write(entry + "\n")

# ====================== PARSER ======================

def parse_http_payload(payload):
    try:
        text = payload.decode(errors="ignore")
        request_line = re.search(r"(GET|POST) (.*?) HTTP/1\.[01]", text)
        if not request_line:
            return None

        method = request_line.group(1)
        uri = request_line.group(2)
        headers = text.split("\r\n\r\n", 1)[0]

        matched_endpoint = None
        for endpoint in WSUS_ENDPOINTS:
            if endpoint.lower() in uri.lower():
                matched_endpoint = endpoint
                break

        return method, uri, headers, matched_endpoint
    except Exception:
        pass

    return None

# ==================== PACKET HANDLER ================

def handle_packet(pkt):
    if pkt.haslayer(TCP) and pkt.haslayer(Raw):
        dport = pkt[TCP].dport
        ip_src = pkt[IP].src
        ip_dst = pkt[IP].dst
        payload = pkt[Raw].load

        if args.port and dport != args.port:
            return

        parsed = parse_http_payload(payload)
        if parsed:
            method, uri, headers, endpoint = parsed
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

            if endpoint:  # WSUS traffic
                wsus_servers.add(f"{ip_dst}:{dport}")
                wsus_clients.add(ip_src)

                entry = (
                    f"\n{RED}[!]{RESET} {BOLD}WSUS Traffic:{RESET} {GREEN}{ip_dst}:{dport}{RESET}\n"
                    f"{timestamp} {CYAN}Client:{RESET} {ip_src} -> Server: {ip_dst}:{dport}\n"
                    f"{YELLOW}Requested URI:{RESET} {uri}\n"
                    f"{MAGENTA}Matched WSUS Endpoint:{RESET} {endpoint}\n"
                    f"{method} {uri}\n{headers}\n{'='*60}"
                )
                log(entry)

            else:  # Non-WSUS HTTP traffic
                print(
                    f"\n{BOLD}Non-WSUS HTTP:{RESET} {ip_dst}:{dport}\n"
                    f"{timestamp} Client: {ip_src} -> Server: {ip_dst}:{dport}\n"
                    f"Requested URI: {uri}\n"
                    f"{method} {uri}\n{headers}\n{'='*60}"
                )

# =================== CTRL+C HANDLER =================

def shutdown_summary(signum, frame):
    print(f"\n\n{MAGENTA}========== WSUSniff Summary =========={RESET}")
    summary = "\n========== WSUSniff Summary ==========\n"

    if wsus_servers:
        print(f"\n{GREEN}WSUS Servers Found:{RESET}")
        summary += "\nWSUS Servers Found:\n"
        for s in sorted(wsus_servers):
            print(f"{GREEN}  - {s}{RESET}")
            summary += f"  - {s}\n"
    else:
        print(f"\n{GREEN}WSUS Servers Found: None{RESET}")
        summary += "\nWSUS Servers Found: None\n"

    if wsus_clients:
        print(f"\n{CYAN}WSUS Clients Found:{RESET}")
        summary += "\nWSUS Clients Found:\n"
        for c in sorted(wsus_clients):
            print(f"{CYAN}  - {c}{RESET}")
            summary += f"  - {c}\n"
    else:
        print(f"\n{CYAN}WSUS Clients Found: None{RESET}")
        summary += "\nWSUS Clients Found: None\n"

    print(f"{MAGENTA}======================================{RESET}\n")
    summary += "======================================\n"

    with open(LOGFILE, "a") as f:
        f.write(summary)

    sys.exit(0)

# ======================= MAIN =======================

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Sniff WSUS HTTP traffic and log endpoint activity.")
    parser.add_argument("-i", "--interface", required=True, help="Interface to sniff (e.g. eth0)")
    parser.add_argument("-p", "--port", type=int, help="Optional port to filter (e.g. 8530). If omitted, all TCP ports are sniffed.")
    args = parser.parse_args()

    print(rf"""{MAGENTA}
 \ \      / / ___|| | | / ___| _ __ (_)/ _|/ _|
  \ \ /\ / /\___ \| | | \___ \| '_ \| | |_| |_ 
   \ V  V /  ___) | |_| |___) | | | | |  _|  _|
    \_/\_/  |____/ \___/|____/|_| |_|_|_| |_|   
{RESET}""")

    if args.port:
        print(f"{BOLD}[*] Starting WSUSniff on interface '{args.interface}' port {args.port}...{RESET}")
    else:
        print(f"{BOLD}[*] Starting WSUSniff on interface '{args.interface}' (all TCP ports)...{RESET}")

    print(f"{YELLOW}[*] Press Ctrl + C to stop logging and see summary.{RESET}\n")

    signal.signal(signal.SIGINT, shutdown_summary)

    sniff(
        iface=args.interface,
        prn=handle_packet,
        store=False,
        filter="tcp"
    )
