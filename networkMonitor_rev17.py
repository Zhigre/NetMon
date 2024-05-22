import tkinter as tk
from tkinter import ttk
from scapy.all import ARP, Ether, srp
import subprocess
import socket
import threading

# Ensure pysnmp is installed
try:
    from pysnmp.hlapi import (
        getCmd, SnmpEngine, CommunityData, UdpTransportTarget, 
        ContextData, ObjectType, ObjectIdentity
    )
except ImportError:
    import os
    os.system('pip install pysnmp')
    from pysnmp.hlapi import (
        getCmd, SnmpEngine, CommunityData, UdpTransportTarget, 
        ContextData, ObjectType, ObjectIdentity
    )

# Global variable to track if the scan has been run at least once
scan_run_once = False
devices = []

def log_message(message):
    terminal_output.config(state=tk.NORMAL)
    terminal_output.insert(tk.END, message + "\n")
    terminal_output.see(tk.END)
    terminal_output.config(state=tk.DISABLED)

def get_ip_address():
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            ip_address = s.getsockname()[0]
        log_message(f"IP address obtained: {ip_address}")
    except Exception as e:
        error_message = f"Error obtaining IP address: {e}"
        log_message(error_message)
        print(error_message)
        ip_address = "N/A"
    return ip_address

def get_network():
    ip_address = get_ip_address()
    parts = ip_address.split('.')
    network = '.'.join(parts[:-1]) + '.0/24'
    log_message(f"Network determined: {network}")
    return network

def arp_scan(network):
    try:
        log_message(f"Starting ARP scan on network: {network}")
        arp = ARP(pdst=network)
        ether = Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = ether/arp
        result = srp(packet, timeout=2, verbose=0)[0]

        devices = []
        for sent, received in result:
            devices.append({'ip': received.psrc, 'mac': received.hwsrc})
            log_message(f"Device found - IP: {received.psrc}, MAC: {received.hwsrc}")
        return devices
    except Exception as e:
        error_message = f"ARP scan failed: {e}"
        log_message(error_message)
        print(error_message)
        return []

def ping_host(ip):
    try:
        log_message(f"Pinging {ip}")
        output = subprocess.check_output(['ping', '-c', '2', ip], stderr=subprocess.STDOUT, universal_newlines=True)
        if "2 packets received" in output:
            log_message(f"Ping successful for {ip}")
            return True
    except subprocess.CalledProcessError as e:
        log_message(f"Ping failed for {ip}: {e}")
        pass
    return False

def get_hostname(ip):
    try:
        hostname = socket.gethostbyaddr(ip)[0]
        log_message(f"Hostname resolved for {ip}: {hostname}")
    except socket.herror:
        hostname = "Unknown"
        log_message(f"Hostname resolution failed for {ip}")
    return hostname

def get_snmp_data(ip, oid):
    try:
        log_message(f"Querying SNMP for {ip} with OID {oid}")
        iterator = getCmd(SnmpEngine(),
                          CommunityData('public', mpModel=0),
                          UdpTransportTarget((ip, 161)),
                          ContextData(),
                          ObjectType(ObjectIdentity(oid)))

        errorIndication, errorStatus, errorIndex, varBinds = next(iterator)

        if errorIndication:
            log_message(f"SNMP error: {errorIndication}")
        elif errorStatus:
            log_message(f"SNMP error: {errorStatus.prettyPrint()}")
        else:
            for varBind in varBinds:
                return str(varBind[1])
    except Exception as e:
        log_message(f"SNMP query failed for {ip}: {e}")
    return "N/A"

def monitor_network():
    global devices
    for row in tree.get_children():
        tree.delete(row)
    
    network = get_network()
    devices = arp_scan(network)

    progress_bar["maximum"] = len(devices)
    progress_bar["value"] = 0

    for index, device in enumerate(devices):
        ip = device['ip']
        mac = device['mac']
        hostname = get_hostname(ip)
        status = "Online" if ping_host(ip) else "Offline"
        snmp_sysdesc = get_snmp_data(ip, '1.3.6.1.2.1.1.1.0')  # SNMPv2-MIB::sysDescr.0
        snmp_sysname = get_snmp_data(ip, '1.3.6.1.2.1.1.5.0')  # SNMPv2-MIB::sysName.0
        color = "green" if status == "Online" else "red"
        tree.insert("", "end", values=(ip, mac, hostname, status, snmp_sysdesc, snmp_sysname), tags=(color,))
        progress_bar["value"] = index + 1
    
    status_label.config(text="Monitoring complete.")
    run_button.config(state=tk.NORMAL)
    run_button.config(text="Re-Run")

def start_monitoring():
    global scan_run_once
    run_button.config(state=tk.DISABLED)
    status_label.config(text="Starting network monitoring...")
    log_message("Starting network monitoring...")
    if not scan_run_once:
        run_button.config(text="Re-Run")
        scan_run_once = True
    threading.Thread(target=monitor_network).start()

def show_host_details(event):
    selected_item = tree.selection()
    if selected_item:
        selected_item = selected_item[0]
        selected_device = tree.item(selected_item, "values")
        
        # Clear previous details
        for widget in details_frame.winfo_children():
            widget.destroy()

        # Display selected host details
        detail_label = ttk.Label(details_frame, text="Host Details", font=("Helvetica", 16, "bold"), background="black", foreground="white")
        detail_label.pack(fill=tk.X, pady=10)

        ip_label = ttk.Label(details_frame, text=f"IP Address: {selected_device[0]}", font=("Helvetica", 12))
        ip_label.pack(pady=5)

        mac_label = ttk.Label(details_frame, text=f"MAC Address: {selected_device[1]}", font=("Helvetica", 12))
        mac_label.pack(pady=5)

        hostname_label = ttk.Label(details_frame, text=f"Hostname: {selected_device[2]}", font=("Helvetica", 12))
        hostname_label.pack(pady=5)

        status_label = ttk.Label(details_frame, text=f"Status: {selected_device[3]}", font=("Helvetica", 12))
        status_label.pack(pady=5)

        snmp_sysdesc_label = ttk.Label(details_frame, text=f"System Description: {selected_device[4]}", font=("Helvetica", 12))
        snmp_sysdesc_label.pack(pady=5)

        snmp_sysname_label = ttk.Label(details_frame, text=f"System Name: {selected_device[5]}", font=("Helvetica", 12))
        snmp_sysname_label.pack(pady=5)

root = tk.Tk()
root.title("Network Monitor")

root.grid_rowconfigure(0, weight=1)
root.grid_columnconfigure(0, weight=1)

font = ("Helvetica", 12)

main_frame = ttk.Frame(root, padding="10")
main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))

main_frame.grid_rowconfigure(2, weight=1)
main_frame.grid_columnconfigure(0, weight=3)
main_frame.grid_columnconfigure(1, weight=1)

fancy_font = ("Helvetica", 20, "italic")
heading_label = ttk.Label(main_frame, text="Network Monitor", font=fancy_font, foreground="green", anchor="center")
heading_label.grid(row=0, column=0, columnspan=2, pady=10, sticky="ew")

description_label = ttk.Label(main_frame, text="This program scans the local network to identify devices and pings them to check if they are online. Click 'Run' to start the monitoring process.", wraplength=380, font=font)
description_label.grid(row=1, column=0, columnspan=2, pady=10)

run_button = ttk.Button(main_frame, text="Run", command=start_monitoring)
run_button.grid(row=2, column=0, columnspan=2, pady=10)

status_label = ttk.Label(main_frame, text="Waiting to start...", font=font)
status_label.grid(row=3, column=0, columnspan=2, pady=10)

progress_bar = ttk.Progressbar(main_frame, orient="horizontal", length=300, mode="determinate")
progress_bar.grid(row=4, column=0, columnspan=2, pady=10)

# Network Devices and Details frame
upper_frame = ttk.Frame(main_frame, padding="10", relief="solid", borderwidth=2, style="Green.TFrame")
upper_frame.grid(row=5, column=0, columnspan=2, sticky=(tk.W, tk.E, tk.N, tk.S))

# Network Devices frame
tree_frame = ttk.Frame(upper_frame, padding="10", relief="solid", borderwidth=2, style="Green.TFrame")
tree_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))

tree_heading_label = ttk.Label(tree_frame, text="Network Devices", font=("Helvetica", 16, "bold"), background="black", foreground="white", anchor="center")
tree_heading_label.pack(fill=tk.X)

columns = ("IP Address", "MAC Address", "Hostname", "Status", "System Description", "System Name")
tree = ttk.Treeview(tree_frame, columns=columns, show="headings")
for col in columns:
    tree.heading(col, text=col)
    tree.column(col, width=150)

tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

scrollbar = ttk.Scrollbar(tree_frame, orient="vertical", command=tree.yview)
tree.configure(yscroll=scrollbar.set)
scrollbar.pack(side=tk.RIGHT, fill="y")

tree.tag_configure("green", foreground="green")
tree.tag_configure("red", foreground="red")

tree.bind("<ButtonRelease-1>", show_host_details)

# Details frame for host details
details_frame = ttk.Frame(upper_frame, padding="10", relief="solid", borderwidth=2, style="Green.TFrame")
details_frame.grid(row=0, column=1, sticky=(tk.W, tk.E, tk.N, tk.S))

details_heading_label = ttk.Label(details_frame, text="Host Details", font=("Helvetica", 16, "bold"), background="black", foreground="white", anchor="center")
details_heading_label.pack(fill=tk.X)

upper_frame.grid_columnconfigure(0, weight=3)
upper_frame.grid_columnconfigure(1, weight=1)
upper_frame.grid_rowconfigure(0, weight=1)

# Terminal output frame
terminal_frame = ttk.Frame(main_frame, padding="10", relief="solid", borderwidth=2, style="Green.TFrame")
terminal_frame.grid(row=6, column=0, columnspan=2, sticky=(tk.W, tk.E, tk.N, tk.S))

terminal_heading_label = ttk.Label(terminal_frame, text="Program Output", font=("Helvetica", 16, "bold"), background="black", foreground="white", anchor="center")
terminal_heading_label.pack(fill=tk.X)

terminal_output = tk.Text(terminal_frame, height=10, state=tk.DISABLED, wrap=tk.WORD)
terminal_output.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

scrollbar_terminal = ttk.Scrollbar(terminal_frame, orient="vertical", command=terminal_output.yview)
terminal_output.configure(yscroll=scrollbar_terminal.set)
scrollbar_terminal.pack(side=tk.RIGHT, fill="y")

# Custom styles
style = ttk.Style()
style.configure("Green.TFrame", bordercolor="green")

root.mainloop()
