<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>ADH_CAPRI - Network Security Testing Suite</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <style>
        body {
            font-family: 'Inter', sans-serif;
        }
        pre {
            background-color: #1f2937;
            padding: 1rem;
            border-radius: 0.5rem;
            color: #e5e7eb;
            overflow-x: auto;
        }
    </style>
</head>
<body class="bg-gray-100 text-gray-800">
    <div class="container mx-auto px-4 py-8 max-w-4xl">
        <!-- Header -->
        <header class="text-center mb-8">
            <img src="https://via.placeholder.com/150x50.png?text=ADH_CAPRI" alt="ADH_CAPRI Logo" class="mx-auto mb-4">
            <h1 class="text-4xl font-bold text-blue-600">ADH_CAPRI</h1>
            <p class="text-xl text-gray-600">Your All-in-One Network Security Testing Suite</p>
        </header>

        <!-- Main Content -->
        <main class="bg-white shadow-lg rounded-lg p-6">
            <!-- Introduction -->
            <section class="mb-8">
                <p class="text-lg">ADH_CAPRI is a Python-based network security testing suite designed for ethical hacking and penetration testing. It includes tools for MAC address changing, network scanning, ARP spoofing, HTTP packet sniffing, and port scanning. This suite is intended for <strong>educational and authorized testing purposes only</strong> and requires root privileges to run.</p>
            </section>

            <!-- Table of Contents -->
            <section class="mb-8">
                <h2 class="text-2xl font-semibold text-blue-600 mb-4">Table of Contents</h2>
                <ul class="list-disc list-inside text-blue-500">
                    <li><a href="#features" class="hover:underline">Features</a></li>
                    <li><a href="#installation" class="hover:underline">Installation</a></li>
                    <li><a href="#usage" class="hover:underline">Usage</a></li>
                    <li><a href="#tool-descriptions" class="hover:underline">Tool Descriptions</a></li>
                    <li><a href="#requirements" class="hover:underline">Requirements</a></li>
                    <li><a href="#screenshots" class="hover:underline">Screenshots</a></li>
                    <li><a href="#logging" class="hover:underline">Logging</a></li>
                    <li><a href="#contributing" class="hover:underline">Contributing</a></li>
                    <li><a href="#disclaimer" class="hover:underline">Disclaimer</a></li>
                    <li><a href="#license" class="hover:underline">License</a></li>
                </ul>
            </section>

            <!-- Features -->
            <section id="features" class="mb-8">
                <h2 class="text-2xl font-semibold text-blue-600 mb-4">Features</h2>
                <ul class="list-disc list-inside space-y-2">
                    <li><strong>MAC Changer</strong>: Modify the MAC address of a network interface.</li>
                    <li><strong>Network Scanner</strong>: Discover devices on a network by scanning IP ranges.</li>
                    <li><strong>ARP Spoofer + HTTP Sniffer</strong>: Perform ARP spoofing to intercept traffic and capture HTTP packets.</li>
                    <li><strong>Port Scanner</strong>: Identify open ports and retrieve service banners on a target host.</li>
                    <li><strong>Full Attack Mode</strong>: Combines MAC changing, network scanning, ARP spoofing, and port scanning in a single workflow.</li>
                    <li>User-friendly command-line interface with colored output for better readability.</li>
                    <li>Comprehensive logging to track tool activities and errors.</li>
                    <li>Modular design for easy extension and maintenance.</li>
                </ul>
            </section>

            <!-- Installation -->
            <section id="installation" class="mb-8">
                <h2 class="text-2xl font-semibold text-blue-600 mb-4">Installation</h2>
                <ol class="list-decimal list-inside space-y-2">
                    <li>
                        <strong>Clone the Repository</strong>:
                        <pre>git clone https://github.com/your-username/ADH_CAPRI.git
cd ADH_CAPRI</pre>
                    </li>
                    <li>
                        <strong>Install Dependencies</strong>:
                        <p>Ensure you have Python 3 installed. Then, install the required Python packages:</p>
                        <pre>pip install -r requirements.txt</pre>
                    </li>
                    <li>
                        <strong>Install System Dependencies</strong>:
                        <p>Ensure <code>ifconfig</code> and <code>sysctl</code> are available on your system. Install <code>scapy</code> dependencies (e.g., <code>libpcap</code>):</p>
                        <pre>sudo apt-get install libpcap-dev</pre>
                    </li>
                    <li>
                        <strong>Run with Root Privileges</strong>:
                        <p>The tool requires root privileges due to low-level network operations:</p>
                        <pre>sudo python3 main.py</pre>
                    </li>
                </ol>
            </section>

            <!-- Usage -->
            <section id="usage" class="mb-8">
                <h2 class="text-2xl font-semibold text-blue-600 mb-4">Usage</h2>
                <ol class="list-decimal list-inside space-y-2">
                    <li>
                        <strong>Launch the Tool</strong>:
                        <pre>sudo python3 main.py</pre>
                    </li>
                    <li>
                        <strong>Menu Options</strong>:
                        <p>Upon launching, the tool displays a menu with the following options:</p>
                        <ul class="list-disc list-inside ml-4">
                            <li><strong>1. MAC Changer</strong>: Change the MAC address of a specified network interface.</li>
                            <li><strong>2. Network Scanner</strong>: Scan a network to discover connected devices.</li>
                            <li><strong>3. ARP Spoofer + HTTP Sniffer</strong>: Perform ARP spoofing and capture HTTP traffic.</li>
                            <li><strong>4. Port Scanner</strong>: Scan for open ports on a target host.</li>
                            <li><strong>5. Full Attack Mode</strong>: Execute a full workflow including MAC changing, network scanning, ARP spoofing, and port scanning.</li>
                            <li><strong>0. Exit</strong>: Exit the tool.</li>
                        </ul>
                    </li>
                    <li>
                        <strong>Input Requirements</strong>:
                        <p>Depending on the selected tool, provide:</p>
                        <ul class="list-disc list-inside ml-4">
                            <li>Network interface (e.g., <code>eth0</code>, <code>wlan0</code>)</li>
                            <li>Target IP or IP range (e.g., <code>192.168.1.0/24</code>)</li>
                            <li>Spoofed IP (e.g., gateway IP for ARP spoofing)</li>
                            <li>New MAC address (e.g., <code>00:11:22:33:44:55</code>)</li>
                            <li>Port range (e.g., <code>1-500</code>)</li>
                            <li>Sniff duration (in seconds, default: 60)</li>
                            <li>Option to sniff HTTP traffic only (default: yes)</li>
                        </ul>
                    </li>
                    <li>
                        <strong>Example Workflow</strong>:
                        <p>Select option <code>3</code> for ARP Spoofer + HTTP Sniffer:</p>
                        <ul class="list-disc list-inside ml-4">
                            <li>Enter the network interface (e.g., <code>eth0</code>).</li>
                            <li>Enter the target IP (e.g., <code>192.168.1.100</code>).</li>
                            <li>Enter the spoofed IP (e.g., <code>192.168.1.1</code>).</li>
                            <li>Choose whether to sniff HTTP only and specify the duration.</li>
                            <li>The tool will enable IP forwarding, start ARP spoofing, and capture HTTP packets.</li>
                        </ul>
                    </li>
                </ol>
            </section>

            <!-- Tool Descriptions -->
            <section id="tool-descriptions" class="mb-8">
                <h2 class="text-2xl font-semibold text-blue-600 mb-4">Tool Descriptions</h2>
                <div class="space-y-4">
                    <div>
                        <h3 class="text-xl font-semibold text-gray-700">1. MAC Changer (<code>mac_changer.py</code>)</h3>
                        <p><strong>Purpose</strong>: Changes the MAC address of a specified network interface.</p>
                        <p><strong>Functionality</strong>:</p>
                        <ul class="list-disc list-inside ml-4">
                            <li>Retrieves the current MAC address using <code>ifconfig</code>.</li>
                            <li>Validates the new MAC address format.</li>
                            <li>Temporarily brings the interface down, changes the MAC, and brings it back up.</li>
                            <li>Verifies the change by checking the new MAC address.</li>
                        </ul>
                        <p><strong>Inputs</strong>:</p>
                        <ul class="list-disc list-inside ml-4">
                            <li>Network interface (e.g., <code>eth0</code>).</li>
                            <li>New MAC address (e.g., <code>00:11:22:33:44:55</code>).</li>
                        </ul>
                    </div>
                    <div>
                        <h3 class="text-xl font-semibold text-gray-700">2. Network Scanner (<code>network_scanner.py</code>)</h3>
                        <p><strong>Purpose</strong>: Discovers devices on a network by sending ARP requests.</p>
                        <p><strong>Functionality</strong>:</p>
                        <ul class="list-disc list-inside ml-4">
                            <li>Sends ARP requests to a specified IP or range.</li>
                            <li>Collects responses to list IP and MAC addresses of connected devices.</li>
                            <li>Displays results in a formatted table.</li>
                        </ul>
                        <p><strong>Inputs</strong>:</p>
                        <ul class="list-disc list-inside ml-4">
                            <li>Target IP or range (e.g., <code>192.168.1.0/24</code>).</li>
                        </ul>
                    </div>
                    <div>
                        <h3 class="text-xl font-semibold text-gray-700">3. ARP Spoofer + HTTP Sniffer (<code>arp_spoofer.py</code>, <code>packet_sniffer.py</code>)</h3>
                        <p><strong>Purpose</strong>: Intercepts network traffic by performing ARP spoofing and captures HTTP packets.</p>
                        <p><strong>Functionality</strong>:</p>
                        <ul class="list-disc list-inside ml-4">
                            <li><strong>ARP Spoofer</strong>: Sends fake ARP packets to associate the attacker's MAC address with the gateway or target IP.</li>
                            <li><strong>HTTP Sniffer</strong>: Captures HTTP packets, extracts URLs, and searches for potential credentials.</li>
                            <li>Runs in separate threads for simultaneous spoofing and sniffing.</li>
                            <li>Automatically enables and disables IP forwarding.</li>
                        </ul>
                        <p><strong>Inputs</strong>:</p>
                        <ul class="list-disc list-inside ml-4">
                            <li>Network interface.</li>
                            <li>Target IP.</li>
                            <li>Spoofed IP (e.g., gateway IP).</li>
                            <li>Sniff duration and HTTP-only option.</li>
                        </ul>
                    </div>
                    <div>
                        <h3 class="text-xl font-semibold text-gray-700">4. Port Scanner (<code>port_scanner.py</code>)</h3>
                        <p><strong>Purpose</strong>: Identifies open ports and retrieves service banners on a target host.</p>
                        <p><strong>Functionality</strong>:</p>
                        <ul class="list-disc list-inside ml-4">
                            <li>Resolves the target IP (supports both IP addresses and hostnames).</li>
                            <li>Scans a specified port range using TCP connect.</li>
                            <li>Collects banners from open ports and displays them.</li>
                        </ul>
                        <p><strong>Inputs</strong>:</p>
                        <ul class="list-disc list-inside ml-4">
                            <li>Target IP or hostname.</li>
                            <li>Port range (e.g., <code>1-500</code>).</li>
                        </ul>
                    </div>
                    <div>
                        <h3 class="text-xl font-semibold text-gray-700">5. Full Attack Mode</h3>
                        <p><strong>Purpose</strong>: Combines all tools into a single workflow for comprehensive testing.</p>
                        <p><strong>Functionality</strong>:</p>
                        <ul class="list-disc list-inside ml-4">
                            <li>Optionally changes the MAC address.</li>
                            <li>Scans the network to discover devices.</li>
                            <li>Performs ARP spoofing and HTTP sniffing on a target device.</li>
                            <li>Scans for open ports on the target.</li>
                        </ul>
                        <p><strong>Inputs</strong>:</p>
                        <ul class="list-disc list-inside ml-4">
                            <li>All inputs required by individual tools.</li>
                        </ul>
                    </div>
                </div>
            </section>

            <!-- Requirements -->
            <section id="requirements" class="mb-8">
                <h2 class="text-2xl font-semibold text-blue-600 mb-4">Requirements</h2>
                <p>The following Python packages are required (listed in <code>requirements.txt</code>):</p>
                <pre>
scapy==2.5.0
IPy==1.1
colorama==0.4.6
pyfiglet==0.8.post1
                </pre>
                <p>Install them using:</p>
                <pre>pip install -r requirements.txt</pre>
                <p><strong>System Requirements</strong>:</p>
                <ul class="list-disc list-inside ml-4">
                    <li>Linux-based system (due to reliance on <code>ifconfig</code> and <code>sysctl</code>).</li>
                    <li>Root privileges (<code>sudo</code>).</li>
                    <li><code>libpcap-dev</code> for <code>scapy</code> functionality.</li>
                </ul>
            </section>

            <!-- Screenshots -->
            <section id="screenshots" class="mb-8">
                <h2 class="text-2xl font-semibold text-blue-600 mb-4">Screenshots</h2>
                <div class="space-y-4">
                    <div>
                        <img src="https://via.placeholder.com/600x300.png?text=ADH_CAPRI+Main+Menu" alt="Main Menu" class="w-full rounded-lg shadow">
                        <p class="text-center text-gray-600">Main menu of ADH_CAPRI displaying available tools.</p>
                    </div>
                    <div>
                        <img src="https://via.placeholder.com/600x300.png?text=Network+Scanner+Output" alt="Network Scan" class="w-full rounded-lg shadow">
                        <p class="text-center text-gray-600">Network scanner output showing discovered devices.</p>
                    </div>
                    <div>
                        <img src="https://via.placeholder.com/600x300.png?text=ARP+Spoofer+Output" alt="ARP Spoofing" class="w-full rounded-lg shadow">
                        <p class="text-center text-gray-600">ARP spoofing and HTTP sniffing in progress.</p>
                    </div>
                </div>
            </section>

            <!-- Logging -->
            <section id="logging" class="mb-8">
                <h2 class="text-2xl font-semibold text-blue-600 mb-4">Logging</h2>
                <p>ADH_CAPRI logs all activities and errors to <code>logs/network_tool.log</code>. The log format includes:</p>
                <ul class="list-disc list-inside ml-4">
                    <li>Timestamp</li>
                    <li>Log level (INFO, ERROR)</li>
                    <li>Message</li>
                </ul>
                <p>Example log entry:</p>
                <pre>2025-09-29 16:00:00,123 - INFO - Starting network scan on 192.168.1.0/24</pre>
                <p>The log directory (<code>logs/</code>) is created automatically if it does not exist.</p>
            </section>

            <!-- Contributing -->
            <section id="contributing" class="mb-8">
                <h2 class="text-2xl font-semibold text-blue-600 mb-4">Contributing</h2>
                <p>Contributions are welcome! To contribute:</p>
                <ol class="list-decimal list-inside space-y-2">
                    <li>Fork the repository.</li>
                    <li>Create a new branch (<code>git checkout -b feature/your-feature</code>).</li>
                    <li>Make your changes and commit (<code>git commit -m 'Add your feature'</code>).</li>
                    <li>Push to the branch (<code>git push origin feature/your-feature</code>).</li>
                    <li>Create a pull request.</li>
                </ol>
                <p>Please ensure your code follows the existing style and includes appropriate logging.</p>
            </section>

            <!-- Disclaimer -->
            <section id="disclaimer" class="mb-8">
                <h2 class="text-2xl font-semibold text-blue-600 mb-4">Disclaimer</h2>
                <p><strong>ADH_CAPRI is intended for educational and authorized testing purposes only.</strong> Unauthorized use of this tool on networks or systems without explicit permission is illegal and unethical. The developers are not responsible for any misuse or damage caused by this tool.</p>
            </section>

            <!-- License -->
            <section id="license" class="mb-8">
                <h2 class="text-2xl font-semibold text-blue-600 mb-4">License</h2>
                <p>This project is licensed under the MIT License. See the <a href="LICENSE" class="text-blue-500 hover:underline">LICENSE</a> file for details.</p>
            </section>
        </main>

        <!-- Footer -->
        <footer class="text-center mt-8 text-gray-600">
            <p>&copy; 2025 ADH_CAPRI. All rights reserved.</p>
        </footer>
    </div>
</body>
</html>
