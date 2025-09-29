# ADH_CAPRI - Network Security Testing Suite

![ADH_CAPRI Logo](https://via.placeholder.com/150x50.png?text=ADH_CAPRI)  
*Your all-in-one toolkit for network security testing and analysis*

ADH_CAPRI is a Python-based network security testing suite designed for ethical hacking and penetration testing. It provides a collection of tools to perform tasks such as MAC address changing, network scanning, ARP spoofing, HTTP packet sniffing, and port scanning. This suite is intended for **educational and authorized testing purposes only** and requires root privileges to run.

---

## Table of Contents
- [Features](#features)
- [Installation](#installation)
- [Usage](#usage)
- [Tool Descriptions](#tool-descriptions)
- [Requirements](#requirements)
- [Screenshots](#screenshots)
- [Logging](#logging)
- [Contributing](#contributing)
- [Disclaimer](#disclaimer)
- [License](#license)

---

## Features
- **MAC Changer**: Modify the MAC address of a network interface.
- **Network Scanner**: Discover devices on a network by scanning IP ranges.
- **ARP Spoofer + HTTP Sniffer**: Perform ARP spoofing to intercept traffic and capture HTTP packets.
- **Port Scanner**: Identify open ports and retrieve service banners on a target host.
- **Full Attack Mode**: Combines MAC changing, network scanning, ARP spoofing, and port scanning in a single workflow.
- User-friendly command-line interface with colored output for better readability.
- Comprehensive logging to track tool activities and errors.
- Modular design for easy extension and maintenance.

---

## Installation

1. **Clone the Repository**:
   ```bash
   git clone https://github.com/your-username/ADH_CAPRI.git
   cd ADH_CAPRI
   ```

2. **Install Dependencies**:
   Ensure you have Python 3 installed. Then, install the required Python packages:
   ```bash
   pip install -r requirements.txt
   ```

3. **Install System Dependencies**:
   - Ensure `ifconfig` and `sysctl` are available on your system (typically included in Linux distributions).
   - Install `scapy` dependencies for packet manipulation (e.g., `libpcap`):
     ```bash
     sudo apt-get install libpcap-dev
     ```

4. **Run with Root Privileges**:
   The tool requires root privileges due to low-level network operations. Use `sudo` to run the script:
   ```bash
   sudo python3 main.py
   ```

---

## Usage

1. **Launch the Tool**:
   Run the main script with root privileges:
   ```bash
   sudo python3 main.py
   ```

2. **Menu Options**:
   Upon launching, the tool displays a menu with the following options:
   - **1. MAC Changer**: Change the MAC address of a specified network interface.
   - **2. Network Scanner**: Scan a network to discover connected devices.
   - **3. ARP Spoofer + HTTP Sniffer**: Perform ARP spoofing and capture HTTP traffic.
   - **4. Port Scanner**: Scan for open ports on a target host.
   - **5. Full Attack Mode**: Execute a full workflow including MAC changing, network scanning, ARP spoofing, and port scanning.
   - **0. Exit**: Exit the tool.

3. **Input Requirements**:
   Depending on the selected tool, you may need to provide:
   - Network interface (e.g., `eth0`, `wlan0`)
   - Target IP or IP range (e.g., `192.168.1.0/24`)
   - Spoofed IP (e.g., gateway IP for ARP spoofing)
   - New MAC address (e.g., `00:11:22:33:44:55`)
   - Port range (e.g., `1-500`)
   - Sniff duration (in seconds, default: 60)
   - Option to sniff HTTP traffic only (default: yes)

4. **Example Workflow**:
   - Select option `3` for ARP Spoofer + HTTP Sniffer.
   - Enter the network interface (e.g., `eth0`).
   - Enter the target IP (e.g., `192.168.1.100`).
   - Enter the spoofed IP (e.g., `192.168.1.1`).
   - Choose whether to sniff HTTP only and specify the duration.
   - The tool will enable IP forwarding, start ARP spoofing, and capture HTTP packets.

---

## Tool Descriptions

### 1. MAC Changer (`mac_changer.py`)
- **Purpose**: Changes the MAC address of a specified network interface.
- **Functionality**:
  - Retrieves the current MAC address using `ifconfig`.
  - Validates the new MAC address format.
  - Temporarily brings the interface down, changes the MAC, and brings it back up.
  - Verifies the change by checking the new MAC address.
- **Inputs**:
  - Network interface (e.g., `eth0`).
  - New MAC address (e.g., `00:11:22:33:44:55`).

### 2. Network Scanner (`network_scanner.py`)
- **Purpose**: Discovers devices on a network by sending ARP requests.
- **Functionality**:
  - Sends ARP requests to a specified IP or range.
  - Collects responses to list IP and MAC addresses of connected devices.
  - Displays results in a formatted table.
- **Inputs**:
  - Target IP or range (e.g., `192.168.1.0/24`).

### 3. ARP Spoofer + HTTP Sniffer (`arp_spoofer.py`, `packet_sniffer.py`)
- **Purpose**: Intercepts network traffic by performing ARP spoofing and captures HTTP packets.
- **Functionality**:
  - **ARP Spoofer**: Sends fake ARP packets to associate the attacker's MAC address with the gateway or target IP, enabling man-in-the-middle attacks.
  - **HTTP Sniffer**: Captures HTTP packets, extracts URLs, and searches for potential credentials (e.g., usernames, passwords) based on a predefined keyword list.
  - Runs in separate threads for simultaneous spoofing and sniffing.
  - Automatically enables and disables IP forwarding.
- **Inputs**:
  - Network interface.
  - Target IP.
  - Spoofed IP (e.g., gateway IP).
  - Sniff duration and HTTP-only option.

### 4. Port Scanner (`port_scanner.py`)
- **Purpose**: Identifies open ports and retrieves service banners on a target host.
- **Functionality**:
  - Resolves the target IP (supports both IP addresses and hostnames).
  - Scans a specified port range using TCP connect.
  - Collects banners from open ports and displays them.
- **Inputs**:
  - Target IP or hostname.
  - Port range (e.g., `1-500`).

### 5. Full Attack Mode
- **Purpose**: Combines all tools into a single workflow for comprehensive testing.
- **Functionality**:
  - Optionally changes the MAC address.
  - Scans the network to discover devices.
  - Performs ARP spoofing and HTTP sniffing on a target device.
  - Scans for open ports on the target.
- **Inputs**:
  - All inputs required by individual tools.

---

## Requirements

The following Python packages are required (listed in `requirements.txt`):
```
scapy==2.5.0
IPy==1.1
colorama==0.4.6
pyfiglet==0.8.post1
```

Install them using:
```bash
pip install -r requirements.txt
```

**System Requirements**:
- Linux-based system (due to reliance on `ifconfig` and `sysctl`).
- Root privileges (`sudo`).
- `libpcap-dev` for `scapy` functionality.

---

## Screenshots

![Main Menu](https://via.placeholder.com/600x300.png?text=ADH_CAPRI+Main+Menu)  
*Main menu of ADH_CAPRI displaying available tools.*

![Network Scan](https://via.placeholder.com/600x300.png?text=Network+Scanner+Output)  
*Network scanner output showing discovered devices.*

![ARP Spoofing](https://via.placeholder.com/600x300.png?text=ARP+Spoofer+Output)  
*ARP spoofing and HTTP sniffing in progress.*

---

## Logging

ADH_CAPRI logs all activities and errors to `logs/network_tool.log`. The log format includes:
- Timestamp
- Log level (INFO, ERROR)
- Message

Example log entry:
```
2025-09-29 16:00:00,123 - INFO - Starting network scan on 192.168.1.0/24
```

The log directory (`logs/`) is created automatically if it does not exist.

---

## Contributing

Contributions are welcome! To contribute:
1. Fork the repository.
2. Create a new branch (`git checkout -b feature/your-feature`).
3. Make your changes and commit (`git commit -m 'Add your feature'`).
4. Push to the branch (`git push origin feature/your-feature`).
5. Create a pull request.

Please ensure your code follows the existing style and includes appropriate logging.

---

## Disclaimer

**ADH_CAPRI is intended for educational and authorized testing purposes only.** Unauthorized use of this tool on networks or systems without explicit permission is illegal and unethical. The developers are not responsible for any misuse or damage caused by this tool.

---

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.
