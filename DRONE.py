import sys
import socket
import platform
import asyncio
from scapy.all import sr1
from colorama import Fore, Style, init
from scapy.layers.inet import ICMP, IP
import argparse
import json

# Initialize colorama to enable colored output on Windows
init(autoreset=True)

# Function to load the port-service mapping from a JSON file
def load_port_list(json_file):
    try:
        with open(json_file, 'r') as file:
            return json.load(file)
    except Exception as e:
        print(f"{Fore.RED}Error loading port list: {str(e)}{Style.RESET_ALL}")
        return {}

# Function to perform a port scan asynchronously on a single port
async def scan_port(ip, port, open_ports, timeout, port_list):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setblocking(False)  # Set non-blocking mode
        await asyncio.wait_for(asyncio.get_event_loop().sock_connect(sock, (ip, port)), timeout=timeout)

        # Check if port is in the port list JSON
        service = port_list.get(str(port), None)
        if not service:
            service = detect_service(ip, port)

        open_ports.append(f"Port {port}: {Fore.GREEN}OPEN{Style.RESET_ALL} - Service: {service}")
        sock.close()
    except (asyncio.TimeoutError, ConnectionRefusedError):
        pass  # Ignore closed/unresponsive ports
    except Exception as e:
        pass  # Handle other exceptions quietly


# Function to perform basic service detection (banner grabbing)
def detect_service(ip, port):
    try:
        # Attempt banner grabbing for other ports
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        sock.connect((ip, port))
        sock.send(b'Hello\r\n')
        banner = sock.recv(1024).decode().strip()
        sock.close()

        # Return banner if it is readable, otherwise return "Unknown service"
        return banner if banner.isprintable() else "Unknown service"
    except Exception as e:
        return "Unknown service"


# Function to perform OS fingerprinting based on TTL values
def os_fingerprint(ip):
    try:
        # Send ICMP packet to the target IP
        packet = IP(dst=ip)/ICMP()
        response = sr1(packet, timeout=1, verbose=0)  # Send the packet and get the response

        if response is None:
            return f"{Fore.RED}No response received. Unable to determine OS.{Style.RESET_ALL}"

        ttl = response.ttl

        # Perform basic OS fingerprinting based on TTL values
        if ttl <= 64:
            return f"{Fore.YELLOW}Linux/Unix-based system (TTL <= 64){Style.RESET_ALL}"
        elif ttl <= 128:
            return f"{Fore.YELLOW}Windows system (TTL <= 128){Style.RESET_ALL}"
        else:
            return f"{Fore.YELLOW}Likely network device (TTL > 128){Style.RESET_ALL}"

    except Exception as e:
        return f"{Fore.RED}Unable to fingerprint OS: {str(e)}{Style.RESET_ALL}"


# Function to perform a scan across a range of ports asynchronously
async def perform_scan(ip, start_port, end_port, os_scan, timeout, port_list):
    open_ports = []
    print(f"{Fore.CYAN}Starting scan on {ip} from port {start_port} to {end_port}...{Style.RESET_ALL}")

    # Perform OS fingerprinting if requested
    if os_scan:
        os_result = os_fingerprint(ip)
        print(f"OS Fingerprint: {os_result}")

    # Create tasks for each port scan and run them concurrently
    tasks = [
        scan_port(ip, port, open_ports, timeout, port_list)
        for port in range(start_port, end_port + 1)
    ]
    await asyncio.gather(*tasks)

    # Display only open ports
    if open_ports:
        for result in open_ports:
            print(result)
    else:
        print(f"{Fore.GREEN}No open ports found.{Style.RESET_ALL}")

    # Inform the user that all other ports are closed
    print(f"{Fore.YELLOW}All other ports in the range {start_port}-{end_port} are closed.{Style.RESET_ALL}")
    print(f"{Fore.GREEN}Scan completed.{Style.RESET_ALL}")


# Function to resolve domain names to IP addresses
def resolve_domain(ip_or_domain):
    try:
        socket.inet_aton(ip_or_domain)
        return ip_or_domain  # Already an IP
    except socket.error:
        try:
            return socket.gethostbyname(ip_or_domain)  # Resolves domain to IP
        except socket.gaierror:
            raise ValueError(f"{Fore.RED}Invalid IP address or domain name.{Style.RESET_ALL}")


# Command-line argument parsing
def parse_args():
    parser = argparse.ArgumentParser(description="DRONE - Advanced Python Network Scanner")
    parser.add_argument('--ip', type=str, required=True, help="Specify the target IP address or domain name.")
    parser.add_argument('--start-port', type=int, default=1, help="Specify the start port for scanning (default 1).")
    parser.add_argument('--end-port', type=int, default=1024, help="Specify the end port for scanning (default 1024).")
    parser.add_argument('--os-scan', action='store_true', help="Perform OS fingerprinting scan.")
    parser.add_argument('--timeout', type=int, default=1, help="Specify timeout in seconds for port scanning (default 1).")
    parser.add_argument('--port-list', type=str, default='ports.json', help="Path to JSON file containing port mappings.")
    return parser.parse_args()


# CLI Input Handling
if __name__ == "__main__":
    args = parse_args()

    # Load port list from JSON
    port_list = load_port_list(args.port_list)

    try:
        ip = resolve_domain(args.ip)
    except ValueError as e:
        print(e)
        sys.exit(1)

    # Run the scan asynchronously
    asyncio.run(perform_scan(ip, args.start_port, args.end_port, args.os_scan, args.timeout, port_list))
