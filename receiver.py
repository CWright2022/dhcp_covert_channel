#!/usr/bin/env python3
from scapy.all import sniff, DHCP, BOOTP
import datetime
import time
import threading
import keyboard

MESSAGE_IN_PROGRESS = False
FILE_IN_PROGRESS = False

def capture_dhcp(iface: str, timeout: int = 10) -> tuple:
    """
    Listen for DHCP packets and collect all lease times (option 51).

    :param iface: network interface to sniff on (e.g., "eth0")
    :param timeout: how many seconds to capture for
    :return: list of lease times (integers, seconds)
    """
    lease_times = []
    message_type = ""

    def handle_packet(pkt):
        nonlocal message_type
        global MESSAGE_IN_PROGRESS
        if pkt.haslayer(DHCP) and pkt.haslayer(BOOTP):
            for opt in pkt[DHCP].options:
                if isinstance(opt, tuple) and opt[0] == "lease_time":
                    if MESSAGE_IN_PROGRESS:
                        # print(f"got {opt[1]}: {chr(opt[1])}")
                        if opt[1] == 0 or opt[1] == 1:
                            MESSAGE_IN_PROGRESS = False
                        else:
                            lease_times.append(chr(opt[1]))
                        break
                    if opt[1] == 0:
                        MESSAGE_IN_PROGRESS = True
                        message_type="text"
                        break
                    if opt[1] == 1:
                        MESSAGE_IN_PROGRESS = True
                        message_type="file"

    print(f"listener ready...")
    sniff(filter="udp and (port 67 or port 68)",
          prn=handle_packet,
          iface=iface,
          store=False,
          stop_filter = stop_filter)
    return message_type, lease_times

def stop_filter(pkt):
        # This function lets sniff() stop when the flag is set
        return not MESSAGE_IN_PROGRESS

def continuous_receive(iface="eth0"):
    print("listening...")
    print("Press Ctrl-C to stop.\n")

    try:
        while True:
            # Run one capture session
            message_type, results = capture_dhcp(iface)

            # Display results if anything was captured
            if message_type:
                print(f"\n[+] Message type: {message_type}")
                print(f"[+] Lease times: {results}")

                if message_type == "text":
                    print("Received text message:")
                    print("".join(results))

                elif message_type == "file":
                    filename = datetime.datetime.now().strftime("%m%d%Y_%H%M%S")
                    with open(filename, "w") as file:
                        for char in results:
                            file.write(char)
                    print(f"Saved file to: {filename}")

            # Small delay between capture sessions
            time.sleep(0.5)

    except KeyboardInterrupt:
        print("quitting...")
        exit()


if __name__ == "__main__":
    iface = "eth0"
    try:
        continuous_receive(iface)
    except KeyboardInterrupt:
        print("quitting...")
        exit()