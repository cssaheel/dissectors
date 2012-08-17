import json

from dissector import *

"""
this file is a test unit for a pcap library (mainly dissector.py
and its associated protocols classes). This library uses and
depends on Scapy library.
"""
# instance of dissector class
dissector = Dissector()
#dissector.change_dfolder("/root/Desktop/aaa")
# sending the pcap file to be dissected
pkts = dissector.dissect_pkts("/root/Desktop/smtp.pcap")

# iterating the dissected packets
for pkt in pkts :
    print(pkt)
#print(pkts["irc"])
#print(json.dumps(pkts["http"], indent=4))
f = open("/root/Desktop/smtp.txt", "w")
#AAAAA = pkts["http"][17]
print(pkts["smtp"])
#if "http" in pkts:
#    pkts.pop("http")
f.write(json.dumps(pkts, indent=4))

#f.write(pkts[26])
#print(pkts["http"][17])
# print (pkts["http"])