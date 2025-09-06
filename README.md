# WSUScripts

A toolkit for discovering and enumerating **Windows Server Update Services (WSUS)** configurations and traffic within an Active Directory environment.  
This repository currently includes two scripts:

- **`wsusniff.py`** – A Python packet sniffer that detects and highlights WSUS HTTP/HTTPS traffic.  
- **`wsuspider.sh`** – A Bash automation wrapper that spiders SYSVOL for WSUS-related Group Policy registry files, decodes them, and extracts WSUS configuration values.

---

## Features

### `wsusniff.py`
- Listens on a given network interface.
- Detects WSUS-specific endpoints such as:
  - `/SimpleAuthWebService/SimpleAuth.asmx`
  - `/ClientWebService/Client.asmx`
- Displays client ↔ server communication including:
  - Source and destination IPs
  - Requested URIs
  - SOAP actions
  - WSUS server hostnames and ports
- Useful for confirming which systems are communicating with WSUS and over what protocol/port.

---

### `wsuspider.sh`
- Automates discovery of WSUS policy configurations distributed via **SYSVOL**.
- Steps:
  1. Runs [manspider](https://github.com/blacklanternsecurity/MANSPIDER) against a target DC to collect `.pol` (registry policy) files.
  2. Decodes downloaded machine registry `.pol` files.
  3. Parses WSUS-related registry keys, including:
     - `WUServer`
     - `WUStatusServer`
     - `UseWUServer`
     - `NoAutoUpdate`
     - `AUOptions`
     - Scheduling and frequency values
- Outputs a summary of discovered WSUS settings to both screen and `wsus_summary.txt`.

---

## Usage

### WSUSniff

```bash
python3 wsusniff.py -i <interface>
```

### WSUSpider
```bash
./wsuspider.sh -dc-ip <DC_IP> -d <DOMAIN> -u <USER> -p <PASSWORD> [--no-banner]
```
Results are saved to wsus_summary.txt

## Requirements

- Python 3.x (`wsusniff.py`)
- [scapy](https://scapy.net/) (for sniffing packets)
- Bash environment (`wsuspider.sh`)
- [manspider](https://github.com/blacklanternsecurity/MANSPIDER)
- `regpol` or equivalent tool to decode `.pol` files
