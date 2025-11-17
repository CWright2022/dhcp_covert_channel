# DHCP Covert Channel  
*CSEC 750 — Fall 2025 — Covert Channel over DHCP*

## Overview  
This repository contains a proof-of-concept covert communication channel that uses DHCP packets to transmit hidden data. The project demonstrates how protocol fields not typically monitored can be used to covertly exfiltrate or exchange information.

The repository includes:

- `sender.py` — sends covert data via DHCP packets  
- `receiver.py` — listens for and reconstructs covert data  
- `secret.txt` — example payload file  
- `go/` — Go code from [another project](https://github.com/CWright2022/dhcpwn) upon which this was based
- `requirements.txt` — Python dependencies

## How It Works  
1. **Sender**  
   - Reads a payload from user input or from a file
   - (if needed) Base64 encode file content
   - Embeds each character into DHCP Discover lease time based on decimal ASCII value
   - Transmits the packets onto the network  

2. **Receiver**  
   - Listens for DHCP packets  
   - Identifies those containing covert data  
   - Extracts lease times
   - Reassembles and decodes them into the original message  

## Getting Started  

### Prerequisites  
- Python 3.x  
- Linux recommended (DHCP operations may require elevated privileges)  
- Dependencies in `requirements.txt`  (`pip install -r requirements.txt`)
- A network where DHCP traffic can be emitted/observed
- Change network interface in sender/receiver programs as appropriate

### Installation  
```bash
git clone https://github.com/CWright2022/dhcp_covert_channel.git
cd dhcp_covert_channel
pip install -r requirements.txt
sudo python3 receiver.py
sudo python3 sender.py
