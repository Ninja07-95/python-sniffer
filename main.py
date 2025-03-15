import socket
import struct
from scapy.all import *
from scapy.layers.inet import *
from scapy.packet import *


# Partie Scapy 
# Partie raw Socket 

# Création d'un socket brut pour capturer tous les paquets
#Analyse de l'en-tête Ethernet (14 octets)

# Seulement IPv4
# Analyse de l'en-tête IP (20 octets)
# Analyse des ports TCP/UDP
