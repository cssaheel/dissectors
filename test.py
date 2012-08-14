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
oo = []
oo.append("hello")
fff = "['hello']"
rep = fff.replace("'", '"')
print(["HHHHHHHHHH"])
print rep
print(json.loads('[["(220) <domain> Service ready -xc90.websitewelcome.com", "ESMTP Exim 4.69 #1 Mon, 05 Oct 2009 01:05:54 -0500  "], ["(220) <domain> Service ready -We", "do not authorize the use of this system to transport unsolicited,  "], ["(220) <domain> Service ready", "and/or bulk e-mail. "]]'))
#fff2 = json.loads(fff, encoding="ascii")
#fff2 = json.loads('["foo", {"bar":["baz", null, 1.0, 2]}]')
#print(fff2[0])
pkts = rdpcap("/root/Desktop/http.cap")
f = open("/root/Desktop/file.txt", "w")
i = 0
#for pkt in pkts:
    #pkt.show()

mydict = {"aa": 1, "bb": 2}
if "aa" in mydict:
    mydict.pop("aa")
    print(mydict)