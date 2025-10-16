#!/usr/bin/env python3
"""
Capture DHCP packets and return all lease times (option 51) seen.
Intended for isolated test networks only.
"""

from scapy.all import sniff, DHCP, BOOTP

MESSAGE_IN_PROGRESS = False

def capture_dhcp(iface: str, timeout: int = 10):
    """
    Listen for DHCP packets and collect all lease times (option 51).

    :param iface: network interface to sniff on (e.g., "eth0")
    :param timeout: how many seconds to capture for
    :return: list of lease times (integers, seconds)
    """
    lease_times = []

    def handle_packet(pkt):
        global MESSAGE_IN_PROGRESS
        if pkt.haslayer(DHCP) and pkt.haslayer(BOOTP):
            for opt in pkt[DHCP].options:
                if isinstance(opt, tuple) and opt[0] == "lease_time":
                    if MESSAGE_IN_PROGRESS:
                        print(f"got {opt[1]}: {chr(opt[1])}")
                        if opt[1] == 0:
                            MESSAGE_IN_PROGRESS = False
                        else:
                            lease_times.append(chr(opt[1]))
                        break
                    if opt[1] == 0:
                        MESSAGE_IN_PROGRESS = True
                        break

    print(f"listener ready...")
    sniff(filter="udp and (port 67 or port 68)",
          prn=handle_packet,
          iface=iface,
          store=False,
          stop_filter = stop_filter)
    return lease_times

def stop_filter(pkt):
        # This function lets sniff() stop when the flag is set
        return not MESSAGE_IN_PROGRESS

if __name__ == "__main__":

    iface = "eth0"

    results = capture_dhcp(iface)
    for char in results:
        print(char, end="")
    print()
