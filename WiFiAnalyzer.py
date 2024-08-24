import tkinter as tk
from tkinter import ttk, scrolledtext, Menu, messagebox, Toplevel, filedialog, simpledialog
from datetime import datetime
import subprocess
import threading
import re
import csv

class WiFiInfoApp:
    def __init__(self, master):
        self.master = master
        self.version = "v0.9 beta"
        master.title(f"WiFi Analyzer {self.version}")
        master.geometry("1200x1000")

        # Create menu
        self.menu_bar = Menu(master)
        master.config(menu=self.menu_bar)

        # File menu
        self.file_menu = Menu(self.menu_bar, tearoff=0)
        self.menu_bar.add_cascade(label="File", menu=self.file_menu)
        self.file_menu.add_command(label="Print", command=self.print_info, accelerator="Ctrl+P")
        self.file_menu.add_command(label="Export", command=self.export_info, accelerator="Ctrl+E")
        self.file_menu.add_separator()
        self.file_menu.add_command(label="Quit", command=self.quit_app, accelerator="Ctrl+Q")

        # Help menu
        self.help_menu = Menu(self.menu_bar, tearoff=0)
        self.menu_bar.add_cascade(label="Help", menu=self.help_menu)
        self.help_menu.add_command(label="About", command=self.show_about, accelerator="F1")

        # Bind keyboard shortcuts
        self.master.bind('<Control-p>', lambda e: self.print_info())
        self.master.bind('<Control-e>', lambda e: self.export_info())
        self.master.bind('<Control-q>', lambda e: self.quit_app())
        self.master.bind('<F1>', lambda e: self.show_about())

        # Create notebook (tabbed interface)
        self.notebook = ttk.Notebook(master)
        self.notebook.pack(fill=tk.BOTH, expand=True)

        # Create main tab
        self.main_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.main_tab, text="Main")

        # Create advanced tab
        self.advanced_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.advanced_tab, text="Advanced Functions")

        # Setup main tab
        self.setup_main_tab()

        # Setup advanced tab
        self.setup_advanced_tab()

        # Version label
        self.version_label = ttk.Label(master, text=f"WiFi Analyzer {self.version}", font=('Arial', 8))
        self.version_label.pack(side=tk.BOTTOM, anchor=tk.SE, padx=5, pady=5)

        # Initial update of fixed info
        self.update_info()

        # Initial update of available networks
        self.update_available_networks()

    def setup_main_tab(self):
        # Frame for fixed info
        self.info_frame = ttk.Frame(self.main_tab, padding=(10, 5))
        self.info_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        # Group 1: Network Identification
        self.group1_frame = ttk.LabelFrame(self.info_frame, text="Network Identification", padding=(10, 5))
        self.group1_frame.grid(row=0, column=0, sticky="nsew", padx=5, pady=5)

        # Group 2: Connection Details
        self.group2_frame = ttk.LabelFrame(self.info_frame, text="Connection Details", padding=(10, 5))
        self.group2_frame.grid(row=0, column=1, sticky="nsew", padx=5, pady=5)

        # Group 3: Hardware Information
        self.group3_frame = ttk.LabelFrame(self.info_frame, text="Hardware Information", padding=(10, 5))
        self.group3_frame.grid(row=1, column=0, sticky="nsew", padx=5, pady=5)

        # Group 4: Performance Metrics
        self.group4_frame = ttk.LabelFrame(self.info_frame, text="Performance Metrics", padding=(10, 5))
        self.group4_frame.grid(row=1, column=1, sticky="nsew", padx=5, pady=5)

        self.info_frame.columnconfigure(0, weight=1)
        self.info_frame.columnconfigure(1, weight=1)
        self.info_frame.rowconfigure(0, weight=1)
        self.info_frame.rowconfigure(1, weight=1)

        # Setup parameter groups
        self.setup_param_groups()

        # Create labels for parameters
        self.info_labels = {}
        for frame, params in self.param_groups.items():
            for i, (param, tooltip) in enumerate(params.items()):
                tooltip_icon = self.create_tooltip_icon(frame, tooltip)
                tooltip_icon.grid(row=i, column=0, sticky='e', padx=(0, 5))
                
                label = ttk.Label(frame, text=f"{param}:")
                label.grid(row=i, column=1, sticky='e', padx=5, pady=2)
                
                # Use Text widget instead of Entry
                self.info_labels[param] = tk.Text(frame, height=1, width=40, wrap=tk.NONE, 
                                                  bg=self.master.cget('bg'), relief=tk.FLAT,
                                                  highlightthickness=0, borderwidth=0)
                self.info_labels[param].grid(row=i, column=2, sticky='w', padx=5, pady=2)
                
                # Make the Text widget read-only
                self.info_labels[param].config(state='disabled')

        # Create frame for available networks
        self.networks_frame = ttk.LabelFrame(self.main_tab, text="Available Networks", padding=(10, 5))
        self.networks_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        # Create treeview for available networks
        columns = ("IN-USE", "SSID", "CHAN", "RATE", "SIGNAL", "BARS", "SECURITY")
        self.networks_tree = ttk.Treeview(self.networks_frame, columns=columns, show="headings")
        self.networks_tree.pack(fill=tk.BOTH, expand=True)

        # Set column headings and widths
        column_widths = {"IN-USE": 5, "SSID": 200, "CHAN": 50, "RATE": 100, "SIGNAL": 60, "BARS": 80, "SECURITY": 100}
        for col in columns:
            self.networks_tree.heading(col, text=col)
            self.networks_tree.column(col, width=column_widths.get(col, 100), anchor="center")

        # Add a scrollbar
        scrollbar = ttk.Scrollbar(self.networks_frame, orient=tk.VERTICAL, command=self.networks_tree.yview)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.networks_tree.configure(yscrollcommand=scrollbar.set)

    def setup_param_groups(self):
        self.param_groups = {
            self.group1_frame: {
                "SSID": "Service Set Identifier: The name of the WiFi network",
                "BSSID": "Basic Service Set Identifier: The MAC address of the access point",
                "Security type": "The type of security used by the WiFi network. Can be Open, WEP, WPA, WPA2-Personal, WPA2-Enterprise, or WPA3. Enterprise versions use more complex authentication methods (like various EAP types including LEAP) often found in corporate environments, frequently involving a RADIUS server for authentication.",
                "Network Mode": "The operating mode of the WiFi network:\n• Infrastructure: Most common mode, where devices connect to a central access point.\n• Ad-Hoc: Direct device-to-device connections without an access point.\n• Mesh: Multiple interconnected access points forming a single network.\n• Master: The device is acting as an access point.\n• Managed: The device is a client connected to an access point (same as Infrastructure).\n\nInfrastructure/Managed mode is typically used in home and office networks.",
                "Connection State": "The current state of the network connection. 'Connected (site only)' indicates a limited connection where only local network resources may be accessible.",
                "Captive Portal URL": "The URL of the captive portal if one is detected, or connection status information."
            },
            self.group2_frame: {
                "IPv4 address": "Internet Protocol version 4 address assigned to your device",
                "IPv6 address": "Internet Protocol version 6 address assigned to your device",
                "Gateway": "The IP address of the router or default gateway",
                "DNS servers": "Domain Name System servers used for resolving domain names",
                "IP Subnet Mask": "The subnet mask determines which part of an IP address belongs to the network and which part belongs to host addresses. It's displayed in dotted decimal notation (e.g., 255.255.255.0).",
                "Public IP": "The public IP address of your internet connection"
            },
            self.group3_frame: {
                "Description": "A brief description of the WiFi adapter",
                "Driver version": "The version of the driver software for the WiFi adapter",
                "Manufacturer": "The company that manufactured the WiFi adapter",
                "Physical address (MAC)": "Media Access Control address: A unique identifier for the network interface",
                "Interface Name": "The name of the WiFi interface used by the system",
				"Power Management": "The current power management status of the WiFi adapter"
            },
            self.group4_frame: {
                "Network band": "Displays the channel width in MHz and the frequency band (2.4 GHz or 5 GHz). Channel width: Wider channels (e.g., 80 MHz) allow higher data rates. Frequency band: 2.4 GHz has better range but more interference, 5 GHz offers faster speeds with shorter range.",
                "Network channel": "The specific channel within the frequency band used for communication",
                "Frequency": "The exact frequency used for the WiFi connection",
                "Signal Strength": "The strength of the WiFi signal, usually measured in dBm",
                "Link Speed": "The current speed of the WiFi connection",
                "TX Power": "Transmit Power: The power output of the WiFi adapter",
            }
        }

    def setup_advanced_tab(self):
        # Frame for buttons
        self.button_frame = ttk.Frame(self.advanced_tab)
        self.button_frame.pack(side=tk.LEFT, fill=tk.Y, padx=(10, 5), pady=10)

        # Create a scrolled text widget for output
        self.output_text = scrolledtext.ScrolledText(self.advanced_tab, wrap=tk.WORD, bg='black', fg='white', font=('Courier', 10))
        self.output_text.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=(5, 10), pady=10)
        
        # Create a button for changing the MAC address
        self.change_mac_button = ttk.Button(self.button_frame, text="Change MAC Address", command=self.change_mac_address, width=20)
        self.change_mac_button.pack(pady=2)

        # Define commands and their corresponding button labels
        self.commands = {
            "Supported Ciphers": "iw phy | grep -A10 'Supported Ciphers:'",
            "VHT Capabilities": "iw phy | grep -A20 'VHT Capabilities'",
            "Regulatory Domain": "iw reg get"
        }
        # Create buttons for each command
        for label, command in self.commands.items():
            button = ttk.Button(self.button_frame, text=label, command=lambda cmd=command, lbl=label: self.run_command(cmd, lbl), width=20)
            button.pack(pady=2)

    def create_tooltip_icon(self, parent, text):
        icon = tk.Label(parent, text="?", font=("Arial", 8), bg="lightgray", fg="black", width=2, height=1)
        icon.bind("<Enter>", lambda event: self.show_tooltip(event, text))
        icon.bind("<Leave>", self.hide_tooltip)
        return icon

    def show_tooltip(self, event, text):
        x = event.x_root + 15
        y = event.y_root + 10
        self.tooltip = tk.Toplevel(self.master)
        self.tooltip.wm_overrideredirect(True)
        self.tooltip.wm_geometry(f"+{x}+{y}")
        label = tk.Label(self.tooltip, text=text, justify='left',
                         background="lightyellow", relief="solid", borderwidth=1,
                         wraplength=250)
        label.pack(ipadx=5, ipady=5)

    def hide_tooltip(self, event=None):
        if hasattr(self, 'tooltip'):
            self.tooltip.destroy()

    def run_command(self, command, label):
        def execute():
            try:
                result = subprocess.check_output(command, shell=True, text=True, stderr=subprocess.STDOUT)
                self.output_text.insert(tk.END, f"--- {label} ---\n{result}\n")
            except subprocess.CalledProcessError as e:
                self.output_text.insert(tk.END, f"--- {label} ---\nError: {e.output}\n")
            self.output_text.see(tk.END)

        # Run the command in a separate thread
        threading.Thread(target=execute).start()
        
    def export_info(self):
        info = self.gather_info()
        file_path = filedialog.asksaveasfilename(defaultextension=".csv",
                                                 filetypes=[("CSV files", "*.csv"), ("Text files", "*.txt"), ("All files", "*.*")])
        if file_path:
            try:
                with open(file_path, 'w', newline='') as csvfile:
                    writer = csv.writer(csvfile)
                    writer.writerow(["Parameter", "Value"])
                    for key, value in info.items():
                        writer.writerow([key, value])
                messagebox.showinfo("Export Successful", f"Information exported to {file_path}")
            except Exception as e:
                messagebox.showerror("Export Failed", f"An error occurred: {str(e)}")

    def gather_info(self):
        info = {}
        for group in self.param_groups.values():
            for param in group.keys():
                if param in self.info_labels:
                    info[param] = self.info_labels[param].get('1.0', tk.END).strip()
        return info

    def get_connection_state(self):
        try:
            state = subprocess.check_output("nmcli -t -f STATE general status", shell=True, text=True).strip()
            return state
        except subprocess.CalledProcessError:
            return "Unable to determine"

    def check_captive_portal(self):
        check_url = "http://nmcheck.gnome.org/check_network_status.txt"
        expected_content = "NetworkManager is online\n"
        try:
            result = subprocess.run(
                ["curl", "-Ls", check_url],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            output = result.stdout.strip()       
            if output == expected_content.strip():
                return "No captive portal"
            elif output.startswith("<!DOCTYPE html") or output.startswith("<html"):
                match = re.search(r'<form.*?action="(https?://[^"]+)"', output, re.DOTALL)
                if match:
                    portal_url = match.group(1)
                    return f"{portal_url}"
                else:
                    return "Captive portal detected, could not extract URL."
            else:
                return f"Unusual response: {output[:50]}..."  # Show first 50 characters
        except subprocess.CalledProcessError as e:
            return "Error checking"
        except subprocess.TimeoutExpired:
            return "Check timed out"
        except Exception as e:
            return "Unexpected error"

    def change_mac_address(self):
       new_mac = simpledialog.askstring("Change MAC Address", "Enter the new MAC address:")
       if new_mac:
            try:
                # Get the interface name
                interface = subprocess.check_output("iw dev | awk '$1==\"Interface\"{print $2}'", shell=True, text=True).strip()

                # Disable the interface
                subprocess.run(f"sudo ip link set {interface} down", shell=True, check=True)

                # Change the MAC address
                subprocess.run(f"sudo ip link set {interface} address {new_mac}", shell=True, check=True)

                # Enable the interface
                subprocess.run(f"sudo ip link set {interface} up", shell=True, check=True)

                messagebox.showinfo("Success", "MAC address changed successfully.")
            except subprocess.CalledProcessError as e:
                messagebox.showerror("Error", f"Failed to change MAC address: {e.output}")
            except Exception as e:
                messagebox.showerror("Error", f"Unexpected error: {e}")

    def get_dns_servers(self):
        try:
            # Try using resolvectl (systemd-resolved)
            result = subprocess.check_output("resolvectl dns | awk '{print $NF}' | sort | uniq", shell=True, text=True).strip()
            if result:
                # Filter out non-IP address information
                dns_servers = [ip for ip in result.split() if self.is_valid_ip(ip)]
                return ' '.join(dns_servers) if dns_servers else "Not available"
        except subprocess.CalledProcessError:
            pass

        try:
            # If resolvectl fails, try using systemd-resolve
            result = subprocess.check_output("systemd-resolve --status | grep 'DNS Servers:' | awk '{print $3}'", shell=True, text=True).strip()
            if result:
                # Filter out non-IP address information
                dns_servers = [ip for ip in result.split() if self.is_valid_ip(ip)]
                return ' '.join(dns_servers) if dns_servers else "Not available"
        except subprocess.CalledProcessError:
            pass

        try:
            # If all else fails, fall back to reading /etc/resolv.conf
            with open('/etc/resolv.conf', 'r') as f:
                dns_servers = [line.split()[1] for line in f if line.startswith('nameserver')]
            return ' '.join(dns_servers) if dns_servers else "Not available"
        except Exception as e:
            print(f"Error reading DNS servers: {e}")
            return "Not available"
    
    def is_valid_ip(self, ip):
        import ipaddress
        try:
            ipaddress.ip_address(ip)
            return True
        except ValueError:
            return False

    def get_security_type(self):
        try:
            # Get the current connection info
            connection_info = subprocess.check_output("nmcli -t -f active,ssid,security dev wifi | grep '^yes'", shell=True, text=True).strip()
            
            if connection_info:
                # Split the connection info
                _, ssid, security = connection_info.split(':')
                
                # Get detailed security info
                detailed_info = subprocess.check_output(f"nmcli -s connection show '{ssid}'", shell=True, text=True).strip()
                
                if "WPA3" in detailed_info:
                    return "WPA3"
                elif "wpa-eap" in detailed_info.lower():
                    eap_method = self.get_eap_method(detailed_info)
                    return f"WPA2-Enterprise ({eap_method})"
                elif "wpa-psk" in detailed_info.lower():
                    return "WPA2-Personal"
                elif security:
                    return security
                else:
                    return "Open"
            
            # If nmcli doesn't work, fall back to iwconfig
            interface = subprocess.check_output("iw dev | awk '$1==\"Interface\"{print $2}'", shell=True, text=True).strip()
            iwconfig_output = subprocess.check_output(f"iwconfig {interface}", shell=True, text=True)
            
            if "Encryption key:on" in iwconfig_output:
                if "WPA3" in iwconfig_output:
                    return "WPA3"
                elif "IEEE 802.1X" in iwconfig_output:
                    return "WPA2-Enterprise"
                elif "IEEE 802.11i/WPA2" in iwconfig_output:
                    return "WPA2-Personal"
                elif "WPA" in iwconfig_output:
                    return "WPA"
                else:
                    return "WEP"
            else:
                return "Open"
        except subprocess.CalledProcessError:
            return "Unable to determine"

    def get_eap_method(self, detailed_info):
        eap_methods = {
            "leap": "LEAP",
            "pwd": "EAP-PWD",
            "md5": "EAP-MD5",
            "tls": "EAP-TLS",
            "fast": "EAP-FAST",
            "ttls": "EAP-TTLS",
            "peap": "PEAP"
        }
        
        for method, name in eap_methods.items():
            if method in detailed_info.lower():
                return name
        
        return "EAP"

    def cidr_to_netmask(self, cidr):
        try:
            cidr = int(cidr)
            mask = (0xffffffff >> (32 - cidr)) << (32 - cidr)
            return f"{mask >> 24 & 255}.{mask >> 16 & 255}.{mask >> 8 & 255}.{mask & 255} (/{cidr})"
        except ValueError:
            return "Invalid CIDR notation"

    def update_info(self):
        max_length = 50  # You can adjust this value as needed

        commands = {
            "SSID": "iwgetid -r",
            "BSSID": "iw dev $(iw dev | awk '$1==\"Interface\"{print $2}') link | grep 'Connected to' | awk '{print $3}'",
            "Security type": self.get_security_type,
            "Network Mode": "iwconfig $(iw dev | awk '$1==\"Interface\"{print $2}') | grep -oP '(?<=Mode:)[^ ]*'",
            "Connection State": self.get_connection_state,
            "Captive Portal URL": self.check_captive_portal,
            "Network band": self.get_network_band_info,
            "Network channel": "iw dev $(iw dev | awk '$1==\"Interface\"{print $2}') info | awk '/channel/ {print $2}' | head -n1",
            "IPv4 address": "ip -4 addr show $(iw dev | awk '$1==\"Interface\"{print $2}') | grep -oP '(?<=inet\\s)\\d+(\.\\d+){3}'",
            "IPv6 address": "ip -6 addr show $(iw dev | awk '$1==\"Interface\"{print $2}') | grep -oP '(?<=inet6\\s)[0-9a-f:]+' | head -n1",
            "Gateway": "ip route | grep default | grep $(iw dev | awk '$1==\"Interface\"{print $2}') | awk '{print $3}'",
            "DNS servers": self.get_dns_servers,
            "IP Subnet Mask": "ip -4 addr show $(iw dev | awk '$1==\"Interface\"{print $2}') | grep -oP '(?<=inet\\s)\\S+' | cut -d'/' -f2",
            "Public IP": "curl -s ifconfig.me",
            "Manufacturer": "lspci -nn | grep Network | cut -d ':' -f3 | cut -d '[' -f1",
            "Description": "lspci -nn | grep Network | cut -d ':' -f3",
            "Driver version": "modinfo $(lspci -k | grep -A3 Network | grep 'Kernel driver' | cut -d ':' -f2 | tr -d ' ') | grep version | head -n1 | awk '{print $2}'",
            "Physical address (MAC)": "ip link show $(iw dev | awk '$1==\"Interface\"{print $2}') | grep 'link/ether' | awk '{print $2}'",
            "Interface Name": "iw dev | awk '$1==\"Interface\"{print $2}'",
            "Link Speed": "iw dev $(iw dev | awk '$1==\"Interface\"{print $2}') link | grep 'bitrate:' | awk '{print $3\" \"$4}'",
            "Frequency": "iw dev $(iw dev | awk '$1==\"Interface\"{print $2}') link | grep 'freq:' | awk '{print $2\" MHz\"}'",
            "Signal Strength": "iw dev $(iw dev | awk '$1==\"Interface\"{print $2}') link | grep 'signal:' | awk '{print $2\" \"$3}'",
            "TX Power": "iw dev $(iw dev | awk '$1==\"Interface\"{print $2}') info | grep 'txpower' | awk '{print $2\" \"$3}'",
			"Power Management": "iwconfig $(iw dev | awk '$1==\"Interface\"{print $2}') | grep 'Power Management:' | awk '{print $NF}'"
        }

        for label, command in commands.items():
            try:
                if callable(command):
                    result = command()
                else:
                    result = subprocess.check_output(command, shell=True, text=True).strip()
            
                if label == "IP Subnet Mask":
                    result = self.cidr_to_netmask(result)

                self.info_labels[label].config(state='normal')
                self.info_labels[label].delete('1.0', tk.END)
            
                # Truncate the result if it's longer than max_length
                truncated_result = (result[:max_length] + '...') if len(result) > max_length else result
                self.info_labels[label].insert('1.0', truncated_result if result else "Not available")
            
                self.info_labels[label].config(state='disabled')

            except subprocess.CalledProcessError:
                self.info_labels[label].config(state='normal')
                self.info_labels[label].delete('1.0', tk.END)
                self.info_labels[label].insert('1.0', "Not available"[:max_length])
                self.info_labels[label].config(state='disabled')

        # Update available networks
        self.update_available_networks()

        # Schedule next update
        self.master.after(25000, self.update_info)
        
    def update_available_networks(self):
        def scan_networks():
            try:
                # Get available networks
                command = "nmcli -t -f IN-USE,SSID,CHAN,RATE,SIGNAL,BARS,SECURITY device wifi list"
                networks = subprocess.check_output(command, shell=True, text=True)
            
                # Process each network
                network_list = []
                for line in networks.strip().split('\n'):
                    fields = line.split(':')
                    if len(fields) == 7:  # Ensure we have all required fields
                        in_use, ssid, chan, rate, signal, bars, security = fields
                    
                        # Clean up fields
                        in_use = '*' if in_use == '*' else ''
                        ssid = ssid if ssid else '--'
                        rate = rate.replace('Mbit/s', '').strip() + ' Mbit/s'
                        network_list.append((in_use, ssid, chan, rate, signal, bars, security))
                    else:
                        print(f"Skipping line due to incorrect number of fields: {fields}")
                
                # Update GUI in the main thread
                self.master.after(0, self.update_network_display, network_list)
            except subprocess.CalledProcessError as e:
                print(f"Failed to update available networks: {e}")
                print(f"Command output: {e.output}")
            except Exception as e:
                print(f"Unexpected error in update_available_networks: {e}")

        # Start the network scanning in a separate thread
        threading.Thread(target=scan_networks).start()

    def update_network_display(self, network_list):
        # Clear existing items
        for item in self.networks_tree.get_children():
            self.networks_tree.delete(item)
        
        # Insert new items
        for network in network_list:
            self.networks_tree.insert("", "end", values=network)

    def get_network_band_info(self):
        try:
            # Get the interface name
            interface = subprocess.check_output("iw dev | awk '$1==\"Interface\"{print $2}'", shell=True, text=True).strip()
            
            # Use iwconfig to get frequency information
            iwconfig_output = subprocess.check_output(f"iwconfig {interface}", shell=True, text=True)
            
            # Parse the output
            freq = None
            for line in iwconfig_output.split('\n'):
                if 'Frequency' in line:
                    freq_match = re.search(r'Frequency:(\d+(\.\d+)?)', line)
                    if freq_match:
                        freq = float(freq_match.group(1))
                    break
            
            # Get channel width using iw
            width_output = subprocess.check_output(f"iw dev {interface} info", shell=True, text=True)
            width = None
            for line in width_output.split('\n'):
                if 'channel' in line and 'width' in line:
                    width_match = re.search(r'width: (\d+) MHz', line)
                    if width_match:
                        width = width_match.group(1)
                    break
            
            # Determine band based on frequency
            if freq is None:
                return "Frequency not available"
            elif freq < 3:
                band = "2.4 GHz"
            elif 3 <= freq < 6:
                band = "5 GHz"
            else:
                band = "6 GHz"
            
            # Format the output
            if width:
                return f"{width} MHz on {band}"
            else:
                return f"Unknown width on {band}"
        except subprocess.CalledProcessError:
            return "Not available"
        except ValueError:
            return "Error parsing frequency"

    def print_info(self):
        messagebox.showinfo("Print", "Print functionality not implemented yet.")

    def quit_app(self):
        self.master.quit()

    def show_about(self):
        about_window = Toplevel(self.master)
        about_window.title("About WiFi Analyzer")
        about_window.geometry("600x300")
    
        # Center the window
        about_window.update_idletasks()
        width = about_window.winfo_width()
        height = about_window.winfo_height()
        x = (about_window.winfo_screenwidth() // 2) - (width // 2)
        y = (about_window.winfo_screenheight() // 2) - (height // 2)
        about_window.geometry('{}x{}+{}+{}'.format(width, height, x, y))
    
        about_text = f"""WiFi Analyzer
        Version: {self.version}

        The WiFi Analyzer Application is a comprehensive, Python-based tool designed to provide unparalleled insights into your WiFi environment. It offers a user-friendly graphical interface that displays a wealth of network parameters, connection details, and performs advanced network diagnostics, all in one intuitive snapshot.

        Developed by dinnerisserver"""
    
        about_label = ttk.Label(about_window, text=about_text, font=('Arial', 12), wraplength=550, justify='center')
        about_label.pack(expand=True)

if __name__ == "__main__":
    root = tk.Tk()
    style = ttk.Style(root)
    style.theme_use('alt')
    app = WiFiInfoApp(root)
    root.mainloop()
