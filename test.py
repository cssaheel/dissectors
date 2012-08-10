'''
Created on Jul 19, 2012

@author: root
'''
from scapy.all import Packet, rdpcap, ConditionalField, Emph, conf
import json
from scapy.layers.dot11 import *
from scapy.layers.ir import *
from scapy.layers.ppp import *
from scapy.layers.gprs import *
from scapy.layers.mobileip import *
from scapy.layers.smb import *
from scapy.layers.bluetooth import *
from scapy.layers.isakmp import *
from scapy.layers.radius import *
from scapy.layers.hsrp import *
from scapy.layers.netbios import *
from scapy.layers.snmp import *
from scapy.layers.dhcp6 import *
from scapy.layers.l2 import *
from scapy.layers.rip import *
from scapy.layers.inet6 import *
from scapy.layers.netflow import *
from scapy.layers.tftp import *
from scapy.layers.dhcp import *
from scapy.layers.l2tp import *
from scapy.layers.rtp import *
from scapy.layers.inet import *
from scapy.layers.ntp import *
from scapy.layers.x509 import *
from scapy.layers.dns import *
from scapy.layers.llmnr import *
from scapy.layers.sebek import *
from scapy.layers.pflog import *
from scapy.layers.dot11 import *
from scapy.layers.mgcp import *
from scapy.layers.skinny import *

v = "hello "
if v[-1:] == " ":
    print("yes")
    v = v.rstrip()
    print(v)
    
dd = {"k1": [1, 2, 3], "k2": [4, 5, 6]}
dd.pop("k1")
print(dd)
hi = "hello"
print(hi[:2] + 'c g')
hi = '"hh'
print(hi)
ssssss = "POPOPOPOP"
myl = list("POPOPOPOP")
print(myl)
print(ssssss[2])
print(24 & 8)

pkts = rdpcap("/root/Desktop/http.cap")
f = open("/root/Desktop/file.txt", "w")
i = 0
#for pkt in pkts:
    #pkt.show()

