import psutil
import tkinter as tk
from scapy.all import sniff
from scapy.layers.dns import DNS, DNSQR
from threading import Thread
from tkinter import ttk
import matplotlib.pyplot as plt
from datetime import datetime
import csv
import os
from tkinter import messagebox  # Fix for messagebox


UPDATE_DELAY = 5  # Update interval in seconds
DATA_FILE = 'network_usage.csv'  # CSV file for logging data

class NetworkMonitorApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Network Usage Monitor")
        self.data = []
        self.websites = {}

        # Treeview for real-time network usage
        self.tree = ttk.Treeview(root, columns=('Interface', 'Download', 'Upload', 'Download Speed', 'Upload Speed'),
                                 show='headings')
        for col in self.tree['columns']:
            self.tree.heading(col, text=col)
        self.tree.pack(fill="both", expand=True)

        # Listbox to show websites visited
        self.website_listbox = tk.Listbox(root, height=10)
        self.website_listbox.pack(fill="both", expand=True)

        # Buttons to trigger data visualization
        self.pie_chart_btn = tk.Button(root, text="Show Website Usage Pie Chart", command=self.show_pie_chart)
        self.pie_chart_btn.pack(pady=5)

        self.graph_btn = tk.Button(root, text="Show Network Data Graph", command=self.show_graph)
        self.graph_btn.pack(pady=5)

        # Update network usage and start sniffing DNS packets
        self.update_usage()
        self.start_sniffing()

    def get_size(self, bytez):
        """Converts bytes to human-readable format."""
        for unit in ['', 'K', 'M', 'G', 'T']:
            if bytez < 1024:
                return f"{bytez:,.2f}{unit}B"
            bytez /= 1024

    def update_usage(self):
        """Updates network usage for all interfaces."""
        io = psutil.net_io_counters(pernic=True)
        self.data.clear()

        for iface, iface_io in io.items():
            if iface == "Software Loopback Interface 1":  # Using your specified interface

                download_speed = iface_io.bytes_recv
                upload_speed = iface_io.bytes_sent
                self.data.append((iface,
                                  self.get_size(iface_io.bytes_recv),
                                  self.get_size(iface_io.bytes_sent),
                                  f"{self.get_size(download_speed / UPDATE_DELAY)}/s",
                                  f"{self.get_size(upload_speed / UPDATE_DELAY)}/s"))
                self.log_data(iface, iface_io.bytes_recv, iface_io.bytes_sent)

        # Clear and update the Treeview
        for row in self.tree.get_children():
            self.tree.delete(row)
        for row in self.data:
            self.tree.insert("", "end", values=row)

        # Schedule the next update
        self.root.after(UPDATE_DELAY * 1000, self.update_usage)

    def log_data(self, iface, download, upload):
        """Logs network usage data to a CSV file."""
        if not os.path.exists(DATA_FILE):
            with open(DATA_FILE, mode='w', newline='') as file:
                writer = csv.writer(file)
                writer.writerow(['Timestamp', 'Interface', 'Download', 'Upload'])

        with open(DATA_FILE, mode='a', newline='') as file:
            writer = csv.writer(file)
            writer.writerow([datetime.now(), iface, download, upload])

    def packet_callback(self, packet):
        """Callback function for sniffing DNS packets."""
        if packet.haslayer(DNS) and packet.getlayer(DNS).qr == 0:
            dns_request = packet.getlayer(DNSQR).qname.decode('utf-8')
            self.website_listbox.insert(tk.END, dns_request)
            self.websites[dns_request] = self.websites.get(dns_request, 0) + 1

    def start_sniffing(self):
        """Starts sniffing DNS packets in a separate thread."""
        Thread(target=lambda: sniff(iface="Software Loopback Interface 1", filter="port 53", prn=self.packet_callback, store=0)).start()

    def show_pie_chart(self):
        """Displays a pie chart of the websites visited."""
        if not self.websites:
            messagebox.showinfo("No Data", "No website data available.")  # Fixed messagebox usage
            return

        websites = list(self.websites.keys())
        visits = list(self.websites.values())

        plt.figure(figsize=(7, 7))
        plt.pie(visits, labels=websites, autopct='%1.1f%%', startangle=90)
        plt.title("Website Visits Distribution")
        plt.axis('equal')  # Equal aspect ratio ensures that pie is drawn as a circle.
        plt.show()

    def show_graph(self):
        """Displays a graph of network usage over time."""
        if not os.path.exists(DATA_FILE):
            messagebox.showinfo("No Data", "No network usage data logged.")  # Fixed messagebox usage
            return

        timestamps, downloads, uploads = [], [], []
        with open(DATA_FILE, mode='r') as file:
            reader = csv.DictReader(file)
            for row in reader:
                timestamps.append(row['Timestamp'])
                downloads.append(int(row['Download']))
                uploads.append(int(row['Upload']))

        plt.figure(figsize=(10, 6))
        plt.plot(timestamps, downloads, label='Download', color='b')
        plt.plot(timestamps, uploads, label='Upload', color='r')
        plt.xlabel('Time')
        plt.ylabel('Bytes')
        plt.title('Network Usage Over Time')
        plt.xticks(rotation=45)
        plt.legend()
        plt.tight_layout()
        plt.show()

if __name__ == "__main__":
    root = tk.Tk()
    app = NetworkMonitorApp(root)
    root.mainloop()