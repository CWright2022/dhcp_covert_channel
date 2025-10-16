from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, UDP
from scapy.layers.dhcp import DHCP, BOOTP
from scapy.sendrecv import sendp
from scapy.arch import get_if_hwaddr
import random

def mac_to_chaddr(mac: str) -> bytes:
    """
    Convert 'aa:bb:cc:dd:ee:ff' to BOOTP chaddr format (16 bytes, zero-padded).
    """
    # Remove colons and convert to bytes
    mac_bytes = bytes.fromhex(mac.replace(":", ""))
    # chaddr field is 16 bytes long in BOOTP
    return mac_bytes + b"\x00" * (16 - len(mac_bytes))

def send_dhcp_discover(lease_time_seconds: int, iface: str, src_mac: str = None):
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

    xid = random.randint(1, 0xFFFFFFFF)

    chaddr = mac_to_chaddr(src_mac)

    # Build packet
    pkt = (
        Ether(dst="ff:ff:ff:ff:ff:ff", src=src_mac) /
        IP(src="0.0.0.0", dst="255.255.255.255") /
        UDP(sport=68, dport=67) /
        BOOTP(op=1, chaddr=chaddr, xid=xid, flags=0x8000) /
        DHCP(
            options=[
                ("message-type", "discover"),
                # DHCP option 51: IP Address Lease Time (seconds)
                ("lease_time", lease_time_seconds),
                # common parameter request list
                ("param_req_list", [1, 3, 6, 15, 51, 58, 59]),
                "end",
            ]
        )
    )

    # print(f"[*] Sending DHCP Discover on iface={iface}, src_mac={src_mac}, requested_lease={lease_time_seconds}s")
    sendp(pkt, iface=iface, verbose=False)
    # print("[+] Packet sent.")

if __name__ == "__main__":
    interface = "eth0"
    mac = None
    message = input("enter your message: ")
    # send init message
    send_dhcp_discover(0, interface, src_mac=mac)
    for char in message:
        print(f"sending {char} ({ord(char)})")
        send_dhcp_discover(ord(char), interface, src_mac=mac)
        input("enter to continue")
    send_dhcp_discover(0, interface, src_mac=mac)