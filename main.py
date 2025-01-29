# ░█░█░█░█░█▀█░█▄█░█▀█░█▀▄░▀█▀
# ░█▀█░█▀▄░█▀█░█░█░█░█░█▀▄░░█░
# ░▀░▀░▀░▀░▀░▀░▀░▀░▀▀▀░▀░▀░▀▀▀             
# Name: main.py
# Description: Networking tool for executing basic commands faster
# Author: hkamori | 0xhkamori.github.io
# ----------------------------------------------
# 🔒    Licensed under the GNU AGPLv3
# 🌐 https://www.gnu.org/licenses/agpl-3.0.html
# ------------------------------------------------   

import os, socket, subprocess

logo = """\n\033[94m
███▄▄▄▄      ▄████████     ███         ███      ▄██████▄   ▄██████▄   ▄█      
███▀▀▀██▄   ███    ███ ▀█████████▄ ▀█████████▄ ███    ███ ███    ███ ███      
███   ███   ███    █▀     ▀███▀▀██    ▀███▀▀██ ███    ███ ███    ███ ███      
███   ███  ▄███▄▄▄         ███   ▀     ███   ▀ ███    ███ ███    ███ ███      
███   ███ ▀▀███▀▀▀         ███         ███     ███    ███ ███    ███ ███      
███   ███   ███    █▄      ███         ███     ███    ███ ███    ███ ███      
███   ███   ███    ███     ███         ███     ███    ███ ███    ███ ███▌    ▄
 ▀█   █▀    ██████████    ▄████▀      ▄████▀    ▀██████▀   ▀██████▀  █████▄▄██
                                                                     ▀        
\n"""

menu_elements = ["[1] Basic Network Information", "[2] Connectivity & Routing", "[3] Security & Firewall", "[4] Advanced Diagnostics"]

bni_elements = {
    "[1] Check IP Address": 'check_ip_address',
    "[2] Check Subnet Mask": 'check_subnet_mask',
    "[3] Check Default Gateway": 'check_default_gateway',
    "[4] Check MAC Address": 'check_mac_address',
    "[5] Check DHCP Status": 'check_dhcp_status',
    "[6] Check DNS Server Address": 'check_dns_server',
    "[7] Check Active Network Connections": 'check_active_connections',
    "[8] Check Network Adapter Status": 'check_network_adapter_status',
    "[9] Check Public IP Address": 'check_public_ip',
    "[10] Check ARP Cache": 'check_arp_cache'
    "[0] Exit"
}

cr_elements = {
    "[1] Check Connectivity to a Server": 'check_connectivity',
    "[2] Check Packet Loss": 'check_packet_loss',
    "[3] Check Number of Hops to Server": 'check_hops_to_server',
    "[4] Check DNS Resolution": 'check_dns_resolution',
    "[5] Check Routing Table": 'check_routing_table',
    "[6] Check for Duplicate IPs": 'check_duplicate_ips',
    "[7] Check Hostname Resolution": 'check_hostname_resolution',
    "[8] Check Network Latency": 'check_network_latency'
    "[0] Exit"
}

sf_elements = {
    "[1] Check Firewall Rules": 'check_firewall_rules',
    "[2] Check Open Ports": 'check_open_ports',
    "[3] Check Internet Speed": 'check_internet_speed',
    "[4] Check MTU Size": 'check_mtu_size',
    "[5] Check VPN Connectivity": 'check_vpn_status',
    "[6] Check Proxy Settings": 'check_proxy_settings',
    "[7] Check Network Policies": 'check_network_policies'
    "[0] Exit"
}

ad_elements = {
    "[8] Check Event Logs for Network Errors": 'check_event_logs',
    "[9] Check Wireless Network Details": 'check_wifi_network_details',
    "[10] Check Network Adapter Power Settings": 'check_adapter_power_settings',
    "[11] Check IPv6 Configuration": 'check_ipv6_config',
    "[12] Check for Malicious Connections": 'check_malicious_connections'
    "[0] Exit"
}

powershell_command = 'powershell -command "(New-Object System.Net.WebClient).DownloadString(\'http://google.com\')"'
def check_ip_address():
    try:
        output = subprocess.check_output("ipconfig /all | findstr IPv4", shell=True, text=True)
        print(output)
    except subprocess.CalledProcessError:
        print("[Error] Unable to retrieve IP address.")

def check_subnet_mask():
    try:
        output = subprocess.check_output("ipconfig /all | findstr Subnet", shell=True, text=True)
        print(output)
    except subprocess.CalledProcessError:
        print("[Error] Unable to retrieve subnet mask.")

def check_default_gateway():
    try:
        output = subprocess.check_output("ipconfig /all | findstr Gateway", shell=True, text=True)
        if output:
            print(output)
        else:
            print("[No Gateway Found]")
    except subprocess.CalledProcessError:
        print("[Error] Unable to retrieve gateway information.")

def check_mac_address():
    try:
        output = subprocess.check_output("getmac", shell=True, text=True)
        print(output)
    except subprocess.CalledProcessError:
        print("[Error] Unable to retrieve MAC address.")

def check_dhcp_status():
    try:
        output = subprocess.check_output("ipconfig /all | findstr DHCP", shell=True, text=True)
        print(output)
    except subprocess.CalledProcessError:
        print("[Error] Unable to retrieve DHCP status.")

def check_dns_server():
    try:
        output = subprocess.check_output("nslookup google.com", shell=True, text=True)
        print(output)
    except subprocess.CalledProcessError as e:
        print(f"[Error] Unable to retrieve DNS server: {e}")

def check_active_connections():
    try:
        output = subprocess.check_output("netstat -ano", shell=True, text=True)
        print(output)
    except subprocess.CalledProcessError:
        print("[Error] Unable to retrieve active connections.")

def check_network_adapter_status():
    try:
        output = subprocess.check_output("ipconfig /all", shell=True, text=True)
        print(output)
    except subprocess.CalledProcessError:
        print("[Error] Unable to retrieve network adapter status.")

def check_public_ip():
    try:
        output = subprocess.check_output("curl ifconfig.me", shell=True, text=True)
        print("Public IP:", output.strip())
    except subprocess.CalledProcessError:
        print("[Error] Unable to retrieve public IP.")
    except FileNotFoundError:
        print("[Error] curl is not installed. Please install curl.")

def check_arp_cache():
    try:
        output = subprocess.check_output("arp -a", shell=True, text=True)
        print(output)
    except subprocess.CalledProcessError:
        print("[Error] Unable to retrieve ARP cache.")

def check_connectivity():
    server = input("[Info] Enter the server hostname or IP to check connectivity. \n> ")
    if server:
        try:
            output = subprocess.check_output(f"ping -n 4 {server}", shell=True, text=True)
            print(output)
        except subprocess.CalledProcessError:
            print("[Error] Ping failed.")

def check_packet_loss():
    server = input("[Info] Enter the server hostname or IP to check packet loss.\n> ")
    if server:
        try:
            output = subprocess.check_output(f"pathping -n {server}", shell=True, text=True)
            print(output)
        except subprocess.CalledProcessError:
            print("[Error] Pathping failed.")

def check_hops_to_server():
    server = input("Enter the server hostname or IP to trace route: ")
    if server:
        try:
            output = subprocess.check_output(f"tracert {server}", shell=True, text=True)
            print(output)
        except subprocess.CalledProcessError:
            print("[Error] Traceroute failed.")

def check_dns_resolution():
    domain = input("[Info] Enter the domain name to resolve.\n> ")
    if domain:
        try:
            output = subprocess.check_output(f"nslookup {domain}", shell=True, text=True)
            print(output)
        except subprocess.CalledProcessError:
            print("[Error] DNS lookup failed.")

def check_routing_table():
    try:
        output = subprocess.check_output("route print", shell=True, text=True)
        print(output)
    except subprocess.CalledProcessError:
        print("[Error] Unable to retrieve routing table.")

def check_duplicate_ips():
    try:
        output = subprocess.check_output("arp -a", shell=True, text=True)
        print(output)
    except subprocess.CalledProcessError:
        print("[Error] Unable to retrieve duplicate IPs.")

def check_hostname_resolution():
    print(f"[Info] Local Hostname: {socket.gethostname()}")

def check_network_latency():
    server = input("[Info] Enter the server hostname or IP to check latency.\n> ")
    if server:
        try:
            output = subprocess.check_output(f"ping -n 4 {server}", shell=True, text=True)
            print(output)
        except subprocess.CalledProcessError:
            print("[Error] Ping failed.")

def check_firewall_rules():
    try:
        output = subprocess.check_output("netsh advfirewall show allprofiles", shell=True, text=True)
        print(output)
    except subprocess.CalledProcessError:
        print("[Error] Unable to retrieve firewall rules.")

def check_open_ports():
    try:
        output = subprocess.check_output("netstat -an", shell=True, text=True)
        print(output)
    except subprocess.CalledProcessError:
        print("[Error] Unable to retrieve open ports.")

def check_internet_speed():
    try:
        output = subprocess.check_output(powershell_command, shell=True, text=True)
        print(output)
    except subprocess.CalledProcessError:
        print("[Error] Unable to retrieve internet speed.")
    except OSError:
        print("[Error] PowerShell not found.")

def check_mtu_size():
    try:
        output = subprocess.check_output("netsh interface ipv4 show subinterfaces", shell=True, text=True)
        print(output)
    except subprocess.CalledProcessError:
        print("[Error] Unable to retrieve MTU size.")

def check_vpn_status():
    try:
        output = subprocess.check_output("ipconfig | findstr VPN", shell=True, text=True)
        print(output)
    except subprocess.CalledProcessError:
        print("[Error] Unable to retrieve VPN status.")

def check_proxy_settings():
    try:
        output = subprocess.check_output("netsh winhttp show proxy", shell=True, text=True)
        print(output)
    except subprocess.CalledProcessError:
        print("[Error] Unable to retrieve proxy settings.")

def check_network_policies():
    try:
        output = subprocess.check_output("gpresult /R | findstr Network", shell=True, text=True)
        print(output)
    except subprocess.CalledProcessError:
        print("[Error] Unable to retrieve network policies.")

def check_event_logs():
    try:
        output = subprocess.check_output("wevtutil qe System /c:10 /rd:true /f:text | findstr /i network", shell=True, text=True)
        print(output)
    except subprocess.CalledProcessError:
        print("[Error] Unable to retrieve event logs.")

def check_wifi_network_details():
    try:
        output = subprocess.check_output("netsh wlan show profiles", shell=True, text=True)
        print(output)
    except subprocess.CalledProcessError:
        print("[Error] Unable to retrieve Wi-Fi network details.")

def check_adapter_power_settings():
    try:
        output = subprocess.check_output("powercfg /devicequery wake_armed", shell=True, text=True)
        print(output)
    except subprocess.CalledProcessError:
        print("[Error] Unable to retrieve adapter power settings.")

def check_ipv6_config():
    try:
        output = subprocess.check_output("ipconfig | findstr IPv6", shell=True, text=True)
        print(output)
    except subprocess.CalledProcessError:
        print("[Error] Unable to retrieve IPv6 configuration.")

def check_malicious_connections():
    try:
        output = subprocess.check_output("netstat -b", shell=True, text=True)
        print(output)
    except subprocess.CalledProcessError:
        print("[Error] Unable to retrieve malicious connections.")

def run(elements):
    print("\nAvailable options:")
    for element in elements:
        print(f"{element}")

    while True:
        choice = input("> ")
        try:
            choice_num = int(choice) - 1
            if 0 <= choice_num < len(elements):
                func_name = elements[list(elements.keys())[choice_num]]
                func = globals().get(func_name)
                if func:
                    func()
                else:
                    print("[Error] Invalid function name.")
            elif choice.lower() == '0':
                return
            elif choice.lower() in ['exit', 'q']:
                exit()
            else:
                print("[Error] Invalid option.")
        except ValueError:
            print("[Error] Invalid input.")

def menu():
    print(logo)
    for element in menu_elements:
        print(element)

    choice = input("> ")
    if choice == "1":
        run(bni_elements)
    elif choice == "2":
        run(cr_elements)
    elif choice == "3":
        run(sf_elements)
    elif choice == "4":
        run(ad_elements)
    else:
        print("[Error] Invalid option.")

menu()
