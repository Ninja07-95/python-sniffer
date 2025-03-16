#!/usr/bin/env python3
"""
Caractéristiques principales :
- Support multi-protocoles (TCP/UDP/ICMP/DNS/HTTP)
- Statistiques en temps réel
- Journalisation des événements
- Filtrage BPF intégré
- Export PCAP et JSON

"""

import sys
import logging
import argparse
import signal
import time
from datetime import datetime
from collections import defaultdict
import json
import socket
import struct
from scapy.all import *
from scapy.layers import dns, http

class AdvancedSniffer:
    def __init__(self, interface=None, filter_exp=None, output_file=None):
        self.interface = interface or conf.iface
        self.filter_exp = filter_exp
        self.output_file = output_file
        self.packet_count = 0
        self.protocol_stats = defaultdict(int)
        self.start_time = time.time()
        self.logger = self.setup_logger()
        self.running = True

        signal.signal(signal.SIGINT, self.signal_handler)

    def setup_logger(self):
        logger = logging.getLogger('ADV_SNIFFER')
        logger.setLevel(logging.INFO)
        handler = logging.FileHandler('sniffer.log')
        formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
        handler.setFormatter(formatter)
        logger.addHandler(handler)
        return logger

    def signal_handler(self, sig, frame):
        self.running = False
        print("\nArrêt en cours... Génération du rapport final.")
        self.generate_report()

    def generate_report(self):
        duration = time.time() - self.start_time
        report = {
            "duration": f"{duration:.2f} secondes",
            "total_packets": self.packet_count,
            "protocols": dict(self.protocol_stats),
            "average_pps": f"{self.packet_count / duration:.2f} p/s"
        }
        print("\n=== Rapport d'analyse ===")
        print(json.dumps(report, indent=4))
        with open("sniffer_report.json", "w") as f:
            json.dump(report, f)

    def packet_handler(self, packet):
        try:
            self.packet_count += 1
            self.process_packet(packet)
            
            if self.output_file:
                wrpcap(self.output_file, packet, append=True)

            if self.packet_count % 50 == 0:
                self.display_stats()

        except Exception as e:
            self.logger.error(f"Erreur de traitement: {str(e)}")

    def process_packet(self, packet):
        if packet.haslayer(IP):
            self.protocol_stats["IP"] +=1
            ip = packet[IP]
            
            if packet.haslayer(TCP):
                self.process_tcp(packet, ip)
            elif packet.haslayer(UDP):
                self.process_udp(packet, ip)
            elif packet.haslayer(ICMP):
                self.process_icmp(packet, ip)
                
            if packet.haslayer(http.HTTPRequest):
                self.process_http(packet)
            elif packet.haslayer(dns.DNS):
                self.process_dns(packet)

    def process_tcp(self, packet, ip):
        self.protocol_stats["TCP"] +=1
        tcp = packet[TCP]
        payload = bytes(tcp.payload)
        self.logger.info(f"TCP {ip.src}:{tcp.sport} -> {ip.dst}:{tcp.dport} | Taille: {len(payload)} octets")

    def process_udp(self, packet, ip):
        self.protocol_stats["UDP"] +=1
        udp = packet[UDP]
        payload = bytes(udp.payload)
        self.logger.info(f"UDP {ip.src}:{udp.sport} -> {ip.dst}:{udp.dport} | Taille: {len(payload)} octets")

    def process_icmp(self, packet, ip):
        self.protocol_stats["ICMP"] +=1
        icmp = packet[ICMP]
        self.logger.info(f"ICMP {ip.src} -> {ip.dst} | Type: {icmp.type}")

    def process_http(self, packet):  # je dois refaire cette partie !!!!!
        self.protocol_stats["HTTP"] +=1
        req = packet[http.HTTPRequest]
        info = {
            "method": req.Method.decode(),
            "host": req.Host.decode(),
            "path": req.Path.decode()
        }
        self.logger.info(f"HTTP Request: {info}")

    def process_dns(self, packet):
        self.protocol_stats["DNS"] +=1
        dns_layer = packet[dns.DNS]
        if dns_layer.qr == 0:
            query = dns_layer.qd.qname.decode()
            self.logger.info(f"DNS Query: {query}")

    def display_stats(self):
        sys.stdout.write("\r" + " " * 50 + "\r")
        sys.stdout.write(f"[Stats] Paquets: {self.packet_count} | Protocoles: {dict(self.protocol_stats)}")
        sys.stdout.flush()

    def start(self):
        print(f"Démarrage du sniffer sur {self.interface} | Filtre: {self.filter_exp or 'Aucun'}")
        self.logger.info(f"Session démarrée - Interface: {self.interface} - Filtre: {self.filter_exp}")
        sniff(iface=self.interface,
              filter=self.filter_exp,
              prn=self.packet_handler,
              store=False,
              stop_filter=lambda x: not self.running)

def main():
    parser = argparse.ArgumentParser(
        description="Sniffer réseau ",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    
    parser.add_argument("-i", "--interface", help="Interface réseau")
    parser.add_argument("-f", "--filter", help="Filtre BPF")
    parser.add_argument("-o", "--output", help="Fichier de sortie PCAP")
    parser.add_argument("-v", "--verbose", action="store_true", help="Mode verbeux")
    
    args = parser.parse_args()
    
    if os.geteuid() != 0:
        print("Erreur : L'exécution nécessite les privilèges root. (sudo)")
        sys.exit(1)

    sniffer = AdvancedSniffer(
        interface=args.interface,
        filter_exp=args.filter,
        output_file=args.output
    )
    
    sniffer.start()

if __name__ == "__main__":
    main()
