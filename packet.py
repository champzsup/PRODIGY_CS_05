from PyQt6.QtWidgets import (
    QApplication, QWidget, QLabel, QPushButton,
    QVBoxLayout, QHBoxLayout, QTextEdit, QFileDialog
)
from PyQt6.QtGui import QIcon
from PyQt6.QtCore import QThread, pyqtSignal
from scapy.all import sniff, wrpcap, Packet, Raw
from scapy.layers.inet import IP
import sys
import datetime


class SniffThread(QThread):
    packet_captured = pyqtSignal(str)

    def __init__(self):
        super().__init__()
        self.running = False
        self.captured_packets = []

    def run(self):
        self.running = True
        sniff(prn=self.process_packet, stop_filter=self.should_stop)

    def stop(self):
        self.running = False

    def should_stop(self, pkt):
        return not self.running

    def process_packet(self, packet: Packet):
        

        if IP in packet:
            src = packet[IP].src
            dst = packet[IP].dst
            proto = packet[IP].proto

            # Translate protocol number
            protocol = {
                6: "TCP",
                17: "UDP",
                1: "ICMP"
            }.get(proto, str(proto))
        else:
            src = dst = "Unknown"
            protocol = "Non-IP Packet"

        # Extract payload if available
        payload = ""
        if Raw in packet:
            try:
                payload = packet[Raw].load.decode(errors="replace")
            except Exception as e:
                payload = repr(packet[Raw].load)  # Show bytes if decoding fails

        # Format display string
        info = (
            f"SRC: {src}  -->  DST: {dst}\n"
            f"Protocol: {protocol}\n"
            f"Payload: {payload}\n"
            + "-" * 60 + "\n"
        )

        self.packet_captured.emit(info)
        self.captured_packets.append(packet)


class NetworkSniffer(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Champz Network Sniffer")
        self.setGeometry(100, 100, 800, 500)
        self.setWindowIcon(QIcon("icon.ico"))  # Add your icon file

        self.sniff_thread = SniffThread()
        self.sniff_thread.packet_captured.connect(self.display_packet)

        # Widgets
        self.start_btn = QPushButton("🔎 Start Sniff")
        self.stop_btn = QPushButton("🛑 Stop Sniff")
        self.save_btn = QPushButton()
        self.save_btn.setIcon(QIcon("download.ico"))

        self.result_output = QTextEdit()
        self.result_output.setReadOnly(True)

        self.packet_count_label = QLabel("Packet: 0")
        self.note = QLabel("Use wireshark for better analysis")

        # Layouts
        button_layout = QHBoxLayout()
        button_layout.addWidget(self.start_btn)
        button_layout.addWidget(self.stop_btn)
        button_layout.addWidget(self.save_btn)

        footer_layout = QHBoxLayout()
        footer_layout.addWidget(self.packet_count_label)
        footer_layout.addWidget(self.note)

        layout = QVBoxLayout()
        layout.addLayout(button_layout)
        layout.addWidget(self.result_output)
        layout.addLayout(footer_layout)

        self.setLayout(layout)

        # Connect
        self.start_btn.clicked.connect(self.start_sniffing)
        self.stop_btn.clicked.connect(self.stop_sniffing)
        self.save_btn.clicked.connect(self.save_packets)

    def start_sniffing(self):
        self.result_output.append("[+] Sniffing started...")
        self.sniff_thread.start()

    def stop_sniffing(self):
        self.result_output.append("[-] Sniffing stopped.")
        self.sniff_thread.stop()

    def save_packets(self):
        filename, _ = QFileDialog.getSaveFileName(self, "Save Capture", "capture.pcap", "PCAP Files (*.pcap)")
        if filename:
            wrpcap(filename, self.sniff_thread.captured_packets)
            self.result_output.append(f"[+] Saved to {filename}")

    def display_packet(self, packet_summary):
        self.result_output.append(packet_summary)
    
    def display_packet(self, packet_summary):
        self.result_output.append(packet_summary)

        count = len(self.sniff_thread.captured_packets)
        self.packet_count_label.setText(f"Packets: {count}")


if __name__ == '__main__':
    app = QApplication(sys.argv)
    sniffer = NetworkSniffer()
    sniffer.show()
    sys.exit(app.exec())
