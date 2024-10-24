
# DRONE - Dynamic Recon and Open Network Exploration

**DRONE** is an advanced Python-based network scanner that performs port scanning, OS fingerprinting, and service detection. It supports asynchronous operations for faster scanning and uses a JSON file to map open ports to detailed descriptions, including protocol, service, and status information.

## Features

- **Port Scanning**: Quickly scan a range of ports to identify which ones are open.
- **Service Detection**: Identify known services running on the open ports using banner grabbing and a JSON port-mapping file.
- **OS Fingerprinting**: Perform basic OS fingerprinting using TTL values from ICMP responses.
- **Customizable Port Mappings**: Reference a JSON file for detailed descriptions of ports, including status (official/unofficial), protocol, and more.
- **Asynchronous Scanning**: Leverages Python's `asyncio` to run scans concurrently for faster results.

## Requirements

- Python 3.x
- [Scapy](https://scapy.net/)
- [Colorama](https://pypi.org/project/colorama/)

To install dependencies, run:

```bash
pip install scapy colorama
```

## Installation

1. **Clone the Repository**:
   ```bash
   git clone https://github.com/yourusername/drone-network-scanner.git
   cd drone-network-scanner
   ```

2. **Set Up the Virtual Environment** (optional but recommended):
   ```bash
   python -m venv .venv
   source .venv/bin/activate  # On Windows: .venv\Scripts\activate
   ```

3. **Install Dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

4. **json credit**:
   I got the JSON from [ports.json GitHub](https://github.com/djcas9/ports.json/blob/54269bbc9c62311b09676e77e514f91d677eda03/ports.lists.json).

## Usage

You can use DRONE from the command line. The following arguments are supported:

```bash
python drone.py --ip <target IP or domain> [options]
```

### Command-Line Arguments:

| Option                      | Description                                                                  |
|------------------------------|------------------------------------------------------------------------------|
| `--ip` (required)            | Specify the target IP address or domain name                                 |
| `--start-port` (default: 1)  | Specify the starting port for scanning (default: 1)                           |
| `--end-port` (default: 1024) | Specify the ending port for scanning (default: 1024)                          |
| `--os-scan`                  | Perform an OS fingerprinting scan based on TTL values                         |
| `--timeout` (default: 1)     | Specify the timeout in seconds for port scanning (default: 1 second)          |
| `--port-list` (default: ports.json) | Path to the JSON file containing port mappings, descriptions, and protocols |

### Examples

1. **Basic Port Scan**:
   ```bash
   python drone.py --ip <target IP or domain>
   ```

2. **Port Scan with OS Fingerprinting**:
   ```bash
   python drone.py --ip <target IP or domain>
   ```

3. **Port Scan for Specific Range**:
   ```bash
   python drone.py --ip <target IP or domain> --start-port 100 --end-port 1000
   ```

## Usage for EXE

If you've compiled the script into an executable (`drone.exe`), you can use it in the same way as the Python script.

Make sure to reference the executable using `./` or `.\` for PowerShell on Windows.

### Examples

1. **Basic Port Scan (EXE)**:
   ```bash
   .\drone.exe --ip <target IP or domain>
   ```

2. **Port Scan with OS Fingerprinting (EXE)**:
   ```bash
   .\drone.exe --ip <target IP or domain> --os-scan
   ```

3. **Port Scan for Specific Range (EXE)**:
   ```bash
   .\drone.exe --ip <target IP or domain> --start-port 100 --end-port 1000
   ```
