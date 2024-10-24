import psutil
import tkinter as tk
from tkinter import ttk
import csv
import os
from datetime import datetime
from tkinter import messagebox
from scapy.all import sniff
from scapy.layers.dns import DNS, DNSQR
from threading import Thread
from utils import get_size
from visualization import Visualization

class NetworkMonitor:
    def __init__(self, root):
        self.root = root
        self.data = []
        self.websites = {}
        
        # Allow the user to select a network interface
        self.interface_var = tk.StringVar()
        interfaces = [iface for iface in psutil.net_if_addrs().keys() if iface != "Loopback Pseudo-Interface 1"]
        self.interface_menu = ttk.Combobox(root, textvariable=self.interface_var, values=interfaces)
        self.interface_menu.pack(pady=5)
        self.interface_menu.set("Select Network Interface")  # Default prompt

        # Real-time network usage display
        self.tree = ttk.Treeview(root, columns=('Interface', 'Download', 'Upload', 'Download Speed', 'Upload Speed'),
                                 show='headings')
        for col in self.tree['columns']:
            self.tree.heading(col, text=col)
        self.tree.pack(fill="both", expand=True)

        # Listbox to show websites visited
        self.website_listbox = tk.Listbox(root, height=10)
        self.website_listbox.pack(fill="both", expand=True)

        # Buttons for visualizations
        self.pie_chart_btn = tk.Button(root, text="Show Website Usage Pie Chart", command=self.show_pie_chart)
        self.pie_chart_btn.pack(pady=5)

        self.graph_btn = tk.Button(root, text="Show Network Data Graph", command=self.show_graph)
        self.graph_btn.pack(pady=5)

        # Ensure the data directory exists
        os.makedirs('data', exist_ok=True)

        # Trigger network usage monitoring after selecting interface
        self.interface_menu.bind("<<ComboboxSelected>>", self.start_monitoring)

    def start_monitoring(self, event):
        """Starts monitoring once an interface is selected."""
        self.selected_interface = self.interface_var.get()
        if self.selected_interface == "Select Network Interface":
            messagebox.showerror("Error", "Please select a network interface.")
        else:
            self.update_network_usage()
            Thread(target=self.start_sniffing).start()  # Start packet sniffing in a separate thread

    def log_data(self, iface, download, upload):
        """Logs network usage data to a CSV file."""
        file_path = os.path.join('data', 'network_usage.csv')
        if not os.path.exists(file_path):
            with open(file_path, mode='w', newline='') as file:
                writer = csv.writer(file)
                writer.writerow(['Timestamp', 'Interface', 'Download', 'Upload'])

        with open(file_path, mode='a', newline='') as file:
            writer = csv.writer(file)
            writer.writerow([datetime.now(), iface, download, upload])

    def update_network_usage(self):
        """Updates network usage statistics."""
        io = psutil.net_io_counters(pernic=True)

        if self.selected_interface in io:
            iface_io = io[self.selected_interface]
            download_speed = iface_io.bytes_recv
            upload_speed = iface_io.bytes_sent

            self.data.clear()
            self.data.append((
                self.selected_interface,
                get_size(iface_io.bytes_recv),
                get_size(iface_io.bytes_sent),
                f"{get_size(download_speed / 5)}/s",
                f"{get_size(upload_speed / 5)}/s"
            ))

            # Log data and update TreeView
            self.log_data(self.selected_interface, iface_io.bytes_recv, iface_io.bytes_sent)

            # Clear and update the Treeview
            for row in self.tree.get_children():
                self.tree.delete(row)
            for row in self.data:
                self.tree.insert("", "end", values=row)

        # Schedule the next update
        self.root.after(5000, self.update_network_usage)

    def packet_callback(self, packet):
        """Callback function for sniffing DNS packets."""
        if packet.haslayer(DNS) and packet.getlayer(DNS).qr == 0:
            dns_request = packet.getlayer(DNSQR).qname.decode('utf-8')
            self.update_website_listbox(dns_request)
            self.websites[dns_request] = self.websites.get(dns_request, 0) + 1

    def start_sniffing(self):
        """Starts sniffing DNS packets."""
        sniff(iface=self.selected_interface, filter="port 53", prn=self.packet_callback, store=0)

    def update_website_listbox(self, website):
        """Updates the listbox with the visited website."""
        self.website_listbox.insert(tk.END, website)

    def show_pie_chart(self):
        Visualization.show_pie_chart(self.websites)

    def show_graph(self):
        Visualization.show_network_graph()
