import sys
import socket
import platform
import asyncio
from scapy.all import sr1
from colorama import Fore, Style, init
from scapy.layers.inet import ICMP, IP
import argparse
import json
import os
import re
from pathlib import Path  # For cross-platform Documents folder access
import datetime  # For timestamped log files
import ctypes  # For accessing Windows folders
from ctypes import wintypes
import time  # For timing functionality
import ipaddress  # For IP range handling

# Initialize colorama to enable colored output on Windows
init(autoreset=True)

# Global variable to hold the log file object
output_file = None

# Function to get the Documents folder on Windows
def get_documents_folder():
    if os.name == 'nt':
        # Use SHGetFolderPathW from shell32.dll to get the path
        CSIDL_PERSONAL = 5  # My Documents
        SHGFP_TYPE_CURRENT = 0
        buf = ctypes.create_unicode_buffer(wintypes.MAX_PATH)
        ctypes.windll.shell32.SHGetFolderPathW(None, CSIDL_PERSONAL, None, SHGFP_TYPE_CURRENT, buf)
        return Path(buf.value)
    else:
        return Path.home() / 'Documents'

# Custom ArgumentParser class to add color to help and error messages
class ColoredArgumentParser(argparse.ArgumentParser):
    def format_help(self):
        help_text = f"{Fore.MAGENTA}DRONE - Advanced Python Network Scanner{Style.RESET_ALL}\n\n"
        help_text += f"{Fore.YELLOW}Usage:{Style.RESET_ALL}\n"
        help_text += f"  {Fore.GREEN}drone.py [-h] --ip IP [--start-port START_PORT] [--end-port END_PORT] [--os-scan] [--timeout TIMEOUT] [--port-list PORT_LIST] [--log-file]{Style.RESET_ALL}\n\n"
        help_text += f"{Fore.YELLOW}Optional arguments:{Style.RESET_ALL}\n"
        help_text += f"  {Fore.GREEN}-h, --help{Style.RESET_ALL}            {Fore.CYAN}Show this help message and exit{Style.RESET_ALL}\n"
        help_text += f"  {Fore.GREEN}--ip IP{Style.RESET_ALL}               {Fore.CYAN}Specify the target IP address, domain name, or CIDR notation (e.g., 192.168.7.0/24){Style.RESET_ALL}\n"
        help_text += f"  {Fore.GREEN}--start-port START_PORT{Style.RESET_ALL} {Fore.CYAN}Specify the start port for scanning (default 1){Style.RESET_ALL}\n"
        help_text += f"  {Fore.GREEN}--end-port END_PORT{Style.RESET_ALL}   {Fore.CYAN}Specify the end port for scanning (default 1024){Style.RESET_ALL}\n"
        help_text += f"  {Fore.GREEN}--os-scan{Style.RESET_ALL}             {Fore.CYAN}Perform OS fingerprinting scan{Style.RESET_ALL}\n"
        help_text += f"  {Fore.GREEN}--timeout TIMEOUT{Style.RESET_ALL}     {Fore.CYAN}Specify timeout in seconds for port scanning (default 1){Style.RESET_ALL}\n"
        help_text += f"  {Fore.GREEN}--port-list PORT_LIST{Style.RESET_ALL}  {Fore.CYAN}Path to JSON file containing port mappings{Style.RESET_ALL}\n"
        help_text += f"  {Fore.GREEN}--log-file{Style.RESET_ALL}            {Fore.CYAN}Output the entire report to a text file in the Documents folder{Style.RESET_ALL}\n"
        return help_text

    def error(self, message):
        sys.stderr.write(f"{Fore.RED}Error: {message}{Style.RESET_ALL}\n")
        self.print_help()
        sys.exit(2)

# Function to strip ANSI escape codes from text
def strip_ansi_codes(text):
    ansi_escape = re.compile(r'\x1B\[[0-?]*[ -/]*[@-~]')
    return ansi_escape.sub('', text)

# Function to print output to console and optionally to a log file
def print_output(msg):
    print(msg)
    if output_file:
        try:
            output_file.write(strip_ansi_codes(msg) + '\n')
        except Exception as e:
            print(f"{Fore.RED}Error writing to log file: {str(e)}{Style.RESET_ALL}")

# Function to load the port-service mapping from a JSON file
def load_port_list(json_file):
    try:
        with open(json_file, 'r') as file:
            return json.load(file)
    except Exception as e:
        print_output(f"{Fore.RED}Error loading port list: {str(e)}{Style.RESET_ALL}")
        return {}

# Function to perform a port scan asynchronously on a single port
async def scan_port(ip, port, open_ports, timeout):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setblocking(False)  # Set non-blocking mode
        await asyncio.wait_for(asyncio.get_event_loop().sock_connect(sock, (ip, port)), timeout=timeout)

        # If connection succeeds, mark as open
        open_ports.append(port)
        sock.close()
    except (asyncio.TimeoutError, ConnectionRefusedError):
        pass  # Ignore closed/unresponsive ports
    except Exception as e:
        print_output(f"{Fore.RED}Error scanning port {port} on {ip}: {str(e)}{Style.RESET_ALL}")
    finally:
        sock.close()  # Ensure the socket is closed in case of any error

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

# Function to check open ports against the JSON port list and display nicely formatted results
def display_results(ip, open_ports, port_list):
    if open_ports:
        for port in open_ports:
            port_info_list = port_list.get(str(port), None)
            if port_info_list and isinstance(port_info_list, list) and len(port_info_list) > 0:
                port_info = port_info_list[0]  # Get the first entry if it's a list

                # Extract relevant data from the JSON
                description = port_info.get('description', 'No description available')
                status = port_info.get('status', 'Unknown status')
                tcp_support = "Yes" if port_info.get('tcp', False) else "No"
                udp_support = "Yes" if port_info.get('udp', False) else "No"

                # Print nicely formatted output with color
                print_output(f"{Fore.GREEN}Port {port} on {ip}{Style.RESET_ALL}")
                print_output(f"{Fore.CYAN}  Description: {description}{Style.RESET_ALL}")
                print_output(f"{Fore.CYAN}  Status: {status}{Style.RESET_ALL}")
                print_output(f"{Fore.CYAN}  TCP Support: {tcp_support}{Style.RESET_ALL}")
                print_output(f"{Fore.CYAN}  UDP Support: {udp_support}{Style.RESET_ALL}")
            else:
                # If no info in JSON, fallback to "Unknown service"
                print_output(f"{Fore.GREEN}Port {port} on {ip}: Unknown service (not in JSON){Style.RESET_ALL}")
    else:
        print_output(f"{Fore.GREEN}No open ports found on {ip}.{Style.RESET_ALL}")

# Function to perform a scan across a range of ports asynchronously
async def perform_scan(ip, start_port, end_port, os_scan, timeout, port_list):
    open_ports = []
    print_output(f"{Fore.CYAN}Starting scan on {ip} from port {start_port} to {end_port}...{Style.RESET_ALL}")

    # Perform OS fingerprinting if requested
    if os_scan:
        os_result = os_fingerprint(ip)
        print_output(f"OS Fingerprint for {ip}: {os_result}")

    # Create tasks for each port scan and run them concurrently
    tasks = [
        scan_port(ip, port, open_ports, timeout)
        for port in range(start_port, end_port + 1)
    ]
    await asyncio.gather(*tasks)

    # Now display the results based on open ports found and JSON data
    display_results(ip, open_ports, port_list)

    # Inform the user that all other ports are closed
    print_output(f"{Fore.YELLOW}All other ports in the range {start_port}-{end_port} are closed on {ip}.{Style.RESET_ALL}")
    print_output(f"{Fore.GREEN}Scan completed for {ip}.{Style.RESET_ALL}")

# Function to resolve domain names to IP addresses or parse CIDR notation
def resolve_domain(ip_or_domain):
    # Check if input is a CIDR notation
    try:
        network = ipaddress.ip_network(ip_or_domain, strict=False)
        return [str(ip) for ip in network.hosts()]  # Return list of IPs in the subnet
    except ValueError:
        pass  # Not a CIDR notation, proceed to check for IP or domain

    # Check if input is an IP address
    try:
        socket.inet_aton(ip_or_domain)
        return [ip_or_domain]  # Return as a list
    except socket.error:
        pass  # Not a valid IP address, proceed to resolve domain

    # Try to resolve as a domain name
    try:
        ip = socket.gethostbyname(ip_or_domain)  # Resolves domain to IP
        return [ip]  # Return as a list
    except socket.gaierror:
        raise ValueError(f"{Fore.RED}Invalid IP address, domain name, or CIDR notation: {ip_or_domain}{Style.RESET_ALL}")

# Command-line argument parsing
def parse_args():
    parser = ColoredArgumentParser(description="DRONE - Advanced Python Network Scanner")
    parser.add_argument('--ip', type=str, required=True, help="Specify the target IP address, domain name, or CIDR notation (e.g., 192.168.7.0/24).")
    parser.add_argument('--start-port', type=int, default=1, help="Specify the start port for scanning (default 1).")
    parser.add_argument('--end-port', type=int, default=1024, help="Specify the end port for scanning (default 1024).")
    parser.add_argument('--os-scan', action='store_true', help="Perform OS fingerprinting scan.")
    parser.add_argument('--timeout', type=int, default=1, help="Specify timeout in seconds for port scanning (default 1).")
    parser.add_argument('--port-list', type=str, default='ports.json', help="Path to JSON file containing port mappings.")
    parser.add_argument('--log-file', action='store_true', help="Output the entire report to a text file in the Documents folder.")
    return parser.parse_args()

# CLI Input Handling
if __name__ == "__main__":
    args = parse_args()

    # Load port list from JSON
    port_list = load_port_list(args.port_list)

    # Set up the log file if --log-file is used
    if args.log_file:
        documents_folder = get_documents_folder()
        timestamp = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
        log_file_name = f"drone_scan_report_{timestamp}.txt"
        log_file_path = documents_folder / log_file_name
        try:
            # Ensure the Documents folder exists
            documents_folder.mkdir(parents=True, exist_ok=True)
            output_file = open(log_file_path, 'w')
        except Exception as e:
            print(f"{Fore.RED}Error opening log file: {str(e)}{Style.RESET_ALL}")
            sys.exit(1)
        else:
            print(f"{Fore.GREEN}Logging to file: {log_file_path}{Style.RESET_ALL}")

    try:
        ip_list = resolve_domain(args.ip)
    except ValueError as e:
        print_output(str(e))
        if output_file:
            output_file.close()
        sys.exit(1)

    # Record the start time
    start_time = time.time()

    # Loop over each IP address and perform the scan
    total_ips = len(ip_list)
    for idx, ip in enumerate(ip_list, 1):
        print_output(f"{Fore.MAGENTA}Scanning IP ({idx}/{total_ips}): {ip}{Style.RESET_ALL}")
        asyncio.run(perform_scan(ip, args.start_port, args.end_port, args.os_scan, args.timeout, port_list))

    # Record the end time
    end_time = time.time()

    # Calculate the total duration
    total_time = end_time - start_time

    # Format the duration into hours, minutes, and seconds
    hours, rem = divmod(total_time, 3600)
    minutes, seconds = divmod(rem, 60)
    time_taken = ""
    if hours > 0:
        time_taken += f"{int(hours)}h "
    if minutes > 0 or hours > 0:
        time_taken += f"{int(minutes)}m "
    time_taken += f"{seconds:.2f}s"

    # Display the total time taken
    print_output(f"{Fore.BLUE}Total time taken: {time_taken}{Style.RESET_ALL}")

    # Close the log file if it was opened
    if output_file:
        print_output(f"{Fore.GREEN}Report saved to {log_file_path}{Style.RESET_ALL}")
        try:
            output_file.close()
        except Exception as e:
            print(f"{Fore.RED}Error closing log file: {str(e)}{Style.RESET_ALL}")
