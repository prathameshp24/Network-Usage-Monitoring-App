import tkinter as tk
from network_monitor import NetworkMonitor
from dns_sniffer import DNSSniffer

if __name__ == "__main__":
    root = tk.Tk()
    monitor = NetworkMonitor(root)
    sniffer = DNSSniffer(monitor)
    sniffer.start_sniffing()  # Start DNS sniffing in a background thread
    root.mainloop()
