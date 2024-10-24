from scapy.all import sniff
from scapy.layers.dns import DNS, DNSQR
from threading import Thread
import csv
import os
from datetime import datetime

class DNSSniffer:
    def __init__(self, network_monitor):
        self.network_monitor = network_monitor

    def packet_callback(self, packet):
        """Processes DNS packets and updates website logs."""
        if packet.haslayer(DNS) and packet.getlayer(DNS).qr == 0:
            dns_request = packet.getlayer(DNSQR).qname.decode('utf-8')
            self.network_monitor.update_website_listbox(dns_request)
            self.log_website_data(dns_request)

    def log_website_data(self, website):
        """Logs or updates website usage data."""
        file_path = os.path.join('data', 'website_usage.csv')
        # Initialize CSV file if it doesn't exist
        if not os.path.exists(file_path):
            with open(file_path, mode='w', newline='') as file:
                writer = csv.writer(file)
                writer.writerow(['Website', 'Time Spent (seconds)', 'Data Transferred (MB)'])

        # Check if website already exists in the file
        existing_data = []
        updated = False
        with open(file_path, mode='r') as file:
            reader = csv.reader(file)
            for row in reader:
                if row[0] == website:
                    time_spent = int(row[1]) + 5  # Add 5 seconds for each packet
                    data_transferred = float(row[2]) + 0.001  # Example: Increase MB data
                    existing_data.append([website, time_spent, data_transferred])
                    updated = True
                else:
                    existing_data.append(row)

        # If not updated, add new row for the website
        if not updated:
            existing_data.append([website, 5, 0.001])

        # Write the updated data back to CSV
        with open(file_path, mode='w', newline='') as file:
            writer = csv.writer(file)
            writer.writerows(existing_data)

    def start_sniffing(self):
        """Starts DNS sniffing in a separate thread."""
        Thread(target=lambda: sniff(filter="port 53", prn=self.packet_callback, store=0)).start()
