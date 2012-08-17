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

print(pkts)

f = open("/root/Desktop/smtp.txt", "w")
print(pkts["smtp"])
f.write(json.dumps(pkts, indent=4))