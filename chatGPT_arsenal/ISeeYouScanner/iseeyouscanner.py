#!/usr/bin/env python3

from scapy.all import *
import argparse
import sys
from ipaddress import ip_address, AddressValueError
import random
import socket

def tcp_scan(target, ports):
    print(f"Starting TCP scan on {target}")
    for port in ports:
        # Craft a SYN packet
        syn_pkt = IP(dst=target)/TCP(dport=port, flags='S')
        # Send the packet and receive a response
        resp = sr1(syn_pkt, timeout=1, verbose=0)
        if resp is None:
            print(f"Port {port}: Filtered or no response")
        elif resp.haslayer(TCP):
            tcp_flags = resp.getlayer(TCP).flags
            if tcp_flags == 0x12:  # SYN-ACK
                print(f"Port {port}: Open")
                # Send RST to gracefully close the connection
                sr(IP(dst=target)/TCP(dport=port, flags='R'), timeout=1, verbose=0)
                # Perform banner grabbing
                banner = grab_banner(target, port)
                if banner:
                    print(f"Port {port} Banner:\n{banner}")
                else:
                    print(f"Port {port}: No banner received")
            elif tcp_flags == 0x14:  # RST-ACK
                pass  # Port is closed, do nothing
            else:
                print(f"Port {port}: Unknown TCP response")
        else:
            print(f"Port {port}: Unknown response")


def grab_banner(target, port):
    try:
        # Create a TCP socket
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(2)
        s.connect((target, port))

        # Prepare the request based on common services
        if port == 80 or port == 8080:
            # Send an HTTP GET request
            s.sendall(b"GET / HTTP/1.1\r\nHost: {}\r\n\r\n".format(target.encode()))
        elif port == 443:
            # For HTTPS, wrap the socket with SSL
            context = ssl.create_default_context()
            s = context.wrap_socket(s, server_hostname=target)
            s.sendall(b"GET / HTTP/1.1\r\nHost: {}\r\n\r\n".format(target.encode()))
        else:
            # Send a generic message
            s.sendall(b"Hello\r\n")

        # Receive data
        banner = s.recv(1024).decode(errors='ignore').strip()
        s.close()
        return banner
    except Exception as e:
        return None

def udp_scan(target, ports):
    print(f"Starting UDP scan on {target}")
    for port in ports:
        # Craft a UDP packet
        udp_pkt = IP(dst=target)/UDP(dport=port)
        # Send the packet and receive a response
        resp = sr1(udp_pkt, timeout=2, verbose=0)
        if resp is None:
            print(f"Port {port}: Open or filtered (no response)")
        elif resp.haslayer(ICMP):
            icmp_type = resp.getlayer(ICMP).type
            icmp_code = resp.getlayer(ICMP).code
            if icmp_type == 3 and icmp_code == 3:
                print(f"Port {port}: Closed (ICMP Port Unreachable received)")
            elif icmp_type == 3 and icmp_code in [1, 2, 9, 10, 13]:
                print(f"Port {port}: Filtered (ICMP type {icmp_type} code {icmp_code})")
            else:
                print(f"Port {port}: Unknown ICMP response (type {icmp_type} code {icmp_code})")
        else:
            print(f"Port {port}: Open or filtered (unexpected response)")

def icmp_scan(target):
    print(f"Starting ICMP scan on {target}")
    # Craft an ICMP Echo Request packet
    icmp_pkt = IP(dst=target)/ICMP()
    resp = sr1(icmp_pkt, timeout=2, verbose=0)
    if resp is None:
        print(f"{target}: Host may be down or blocking ICMP")
    elif int(resp.getlayer(ICMP).type) == 0:
        print(f"{target}: Host is up (ICMP Echo Reply received)")
    else:
        print(f"{target}: Unexpected ICMP response (type {resp.getlayer(ICMP).type})")

def parse_ports(port_str):
    ports = set()
    if port_str.lower() == 'all':
        return list(range(1, 65536))
    else:
        port_parts = port_str.split(',')
        for part in port_parts:
            part = part.strip()
            if '-' in part:
                try:
                    start_port, end_port = map(int, part.split('-'))
                    if start_port > end_port or not (1 <= start_port <= 65535) or not (1 <= end_port <= 65535):
                        print(f"Invalid port range '{part}'. Ports must be between 1 and 65535.")
                        sys.exit(1)
                    ports.update(range(start_port, end_port+1))
                except ValueError:
                    print(f"Invalid port range '{part}'.")
                    sys.exit(1)
            else:
                try:
                    port = int(part)
                    if not (1 <= port <= 65535):
                        print(f"Invalid port '{part}'. Ports must be between 1 and 65535.")
                        sys.exit(1)
                    ports.add(port)
                except ValueError:
                    print(f"Invalid port '{part}'.")
                    sys.exit(1)
        return sorted(ports)

def main():
    parser = argparse.ArgumentParser(description="ISeeYou Network Scanner")
    parser.add_argument("target", help="Target IP address or hostname")
    parser.add_argument("--tcp", action='store_true', help="Perform TCP scan")
    parser.add_argument("--udp", action='store_true', help="Perform UDP scan")
    parser.add_argument("--icmp", action='store_true', help="Perform ICMP scan")
    parser.add_argument("--ports", type=str, default="80,443", help="Ports to scan: comma-separated list of ports and/or ranges (e.g., 22,80-443,1000), or 'all' for all ports")
    args = parser.parse_args()

    # Validate target IP address or resolve hostname
    try:
        target_ip = str(ip_address(args.target))
    except ValueError:
        # Try resolving hostname
        try:
            target_ip = socket.gethostbyname(args.target)
        except socket.gaierror:
            print(f"Could not resolve hostname '{args.target}'.")
            sys.exit(1)

    # Parse ports
    ports = parse_ports(args.ports)

    # Randomize port order to evade basic detection
    random.shuffle(ports)

    # Check if at least one protocol is selected
    if not (args.tcp or args.udp or args.icmp):
        print("Please specify at least one protocol to scan (--tcp, --udp, --icmp)")
        sys.exit(1)

    # Perform scans based on flags
    if args.tcp:
        tcp_scan(target_ip, ports)
    if args.udp:
        udp_scan(target_ip, ports)
    if args.icmp:
        icmp_scan(target_ip)

if __name__ == "__main__":
    main()

