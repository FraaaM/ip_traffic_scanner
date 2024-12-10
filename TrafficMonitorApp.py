import scapy.all as scapy
from tkinter import Tk, Frame, Label, Button, ttk
import threading
import subprocess


class TrafficMonitor:
    def __init__(self, root_window):
        self.root = root_window
        self.root.title("Network Traffic Monitor")
        self.root.geometry("1270x335")

        self.packet_counts = {}
        self.suspicious_addresses = set()
        self.banned_addresses = set()
        self.is_monitoring = False

        # GUI Components
        self.setup_gui()

    def setup_gui(self):
        # Frames for sections
        frame_all_ips = Frame(self.root)
        frame_all_ips.grid(row=0, column=0, padx=10, pady=10)

        frame_suspicious_ips = Frame(self.root)
        frame_suspicious_ips.grid(row=0, column=1, padx=10, pady=10)

        frame_banned_ips = Frame(self.root)
        frame_banned_ips.grid(row=0, column=2, padx=10, pady=10)

        # Table for all IPs
        Label(frame_all_ips, text="All Incoming IPs").pack()
        self.table_all_ips = ttk.Treeview(frame_all_ips, columns=("IP", "Port", "Size"), show="headings", height=10)
        self.table_all_ips.heading("IP", text="IP Address")
        self.table_all_ips.heading("Port", text="Port")
        self.table_all_ips.heading("Size", text="Packet Size")
        self.table_all_ips.pack(fill="both", expand=True)

        self.start_button = Button(frame_all_ips, text="Start Monitoring", command=self.start_sniffing)
        self.start_button.pack(fill="x", pady=5)
        self.stop_button = Button(frame_all_ips, text="Stop Monitoring", command=self.stop_sniffing, state="disabled")
        self.stop_button.pack(fill="x")

        # Table for suspicious IPs
        Label(frame_suspicious_ips, text="Suspicious IPs").pack()
        self.table_suspicious_ips = ttk.Treeview(frame_suspicious_ips, columns=("IP", "Reason"), show="headings", height=10)
        self.table_suspicious_ips.heading("IP", text="IP Address")
        self.table_suspicious_ips.heading("Reason", text="Reason")
        self.table_suspicious_ips.pack(fill="both", expand=True)

        self.block_button = Button(frame_suspicious_ips, text="Block Selected IP", command=self.block_ip)
        self.block_button.pack(fill="x", pady=5)

        # Table for blocked IPs
        Label(frame_banned_ips, text="Blocked IPs").pack()
        self.table_banned_ips = ttk.Treeview(frame_banned_ips, columns=("IP",), show="headings", height=10)
        self.table_banned_ips.heading("IP", text="IP Address")
        self.table_banned_ips.pack(fill="both", expand=True)

        self.unblock_button = Button(frame_banned_ips, text="Unblock Selected IP", command=self.unblock_ip)
        self.unblock_button.pack(fill="x", pady=5)

    def packet_handler(self, pkt):
        if pkt.haslayer(scapy.IP):
            ip = pkt[scapy.IP].src
            size = len(pkt)

            self.packet_counts[ip] = self.packet_counts.get(ip, 0) + size

            if self.packet_counts[ip] > 200 and ip not in self.suspicious_addresses:
                self.suspicious_addresses.add(ip)
                self.table_suspicious_ips.insert("", "end", values=(ip, "High Traffic"))

            if ip not in self.banned_addresses:
                self.table_all_ips.insert("", "end", values=(ip, pkt[scapy.IP].sport, size))

    def start_sniffing(self):
        self.is_monitoring = True
        self.start_button.config(state="disabled")
        self.stop_button.config(state="normal")

        sniff_thread = threading.Thread(target=lambda: scapy.sniff(prn=self.packet_handler, store=False))
        sniff_thread.daemon = True
        sniff_thread.start()

    def stop_sniffing(self):
        self.is_monitoring = False
        self.start_button.config(state="normal")
        self.stop_button.config(state="disabled")

    def block_ip(self):
        selected = self.table_suspicious_ips.selection()
        if selected:
            ip = self.table_suspicious_ips.item(selected[0], "values")[0]
            if ip not in self.banned_addresses:
                self.banned_addresses.add(ip)
                self.table_banned_ips.insert("", "end", values=(ip,))
                self.add_iptables_rule(ip)
                self.table_suspicious_ips.delete(selected[0])

    def unblock_ip(self):
        selected = self.table_banned_ips.selection()
        if selected:
            ip = self.table_banned_ips.item(selected[0], "values")[0]
            if ip in self.banned_addresses:
                self.banned_addresses.remove(ip)
                self.remove_iptables_rule(ip)
                self.table_banned_ips.delete(selected[0])

    def add_iptables_rule(self, ip_address):
        try:
            subprocess.run(["sudo", "iptables", "-A", "INPUT", "-s", ip_address, "-j", "DROP"], check=True)
            print(f"Blocked IP address: {ip_address}")
        except subprocess.CalledProcessError as e:
            print(f"Error blocking IP address {ip_address}: {e}")

    def remove_iptables_rule(self, ip_address):
        try:
            while True:
                result = subprocess.run(["sudo", "iptables", "-D", "INPUT", "-s", ip_address, "-j", "DROP"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                if result.returncode != 0:
                    break
            print(f"Unblocked IP address: {ip_address}")
        except subprocess.CalledProcessError as e:
            print(f"Error unblocking IP address {ip_address}: {e}")


if __name__ == "__main__":
    root = Tk()
    app = TrafficMonitor(root)
    root.mainloop()
    
