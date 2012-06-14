'''
Created on Jun 12, 2012

@author: root
'''
from scapy.all import Packet
from scapy.utils import rdpcap
from scapy.layers.inet import IP,TCP,UDP
from scapy.fields import StrField,ConditionalField,Emph,PacketListField
from scapy.config import conf
from scapy.base_classes import BasePacket,Gen,SetGen,Packet_metaclass,NewDefaultValues

class packet:
    packetslist = rdpcap("/root/Desktop/dump.cap")
    pack = packetslist[2].getlayer("TCP")
    #packetslist[0].show()
    #print(pack.getlayer(UDP).show())
    #print(pack.getlayer(UDP).summary())
    #pack = packetslist[0].getlayer("IP")
    
    if pack.name == "Ethernet":
        print(pack.fields["dst"])
        print(pack.fields["src"])
        print(pack.fields["type"])
        
    if pack.name == "802.3":
        print(pack.fields["dst"])
        print(pack.fields["src"])
        print(pack.fields["len"])
        
    if pack.name == "LLC":
        print(pack.fields["dsap"])
        print(pack.fields["ssap"])
        print(pack.fields["ctrl"])
        
    if pack.name == "cooked linux":
        print(pack.fields["pkttype"])
        print(pack.fields["lladdrtype"])
        print(pack.fields["lladdrlen"])
        print(pack.fields["src"])
        print(pack.fields["proto"])
        
    if pack.name == "SNAP":
        print(pack.fields["OUI"])
        print(pack.fields["code"])

    if pack.name == "802.1Q":
        print(pack.fields["prio"])
        print(pack.fields["id"])
        print(pack.fields["vlan"])
        print(pack.fields["type"])
        
    if pack.name == "Spanning Tree Protocol":
        print(pack.fields["proto"])
        print(pack.fields["version"])
        print(pack.fields["bpdutype"])
        print(pack.fields["bpduflags"])
        print(pack.fields["rootid"])
        print(pack.fields["rootmac"])
        print(pack.fields["pathcost"])
        print(pack.fields["bridgeid"])
        print(pack.fields["bridgemac"])
        print(pack.fields["portid"])
        print(pack.fields["age"])
        print(pack.fields["maxage"])
        print(pack.fields["hellotime"])
        print(pack.fields["fwddelay"])
        
        
    if pack.name == "EAPOL":
        print(pack.fields["version"])
        print(pack.fields["type"])
        print(pack.fields["len"])
        
    if pack.name == "EAP":
        print(pack.fields["code"])
        print(pack.fields["id"])
        print(pack.fields["len"])
        print(pack.fields["type"])
        
    if pack.name == "ARP":
        print(pack.fields["hwtype"])
        print(pack.fields["ptype"])
        print(pack.fields["hwlen"])
        print(pack.fields["plen"])
        print(pack.fields["op"])
        print(pack.fields["hwsrc"])
        print(pack.fields["psrc"])
        print(pack.fields["hwdst"])
        print(pack.fields["pdst"])
        
    if pack.name == "GRE":
        print(pack.fields["chksumpresent"])
        print(pack.fields["reserved0"])
        print(pack.fields["version"])
        print(pack.fields["proto"])
        print(pack.fields["chksum"])
        print(pack.fields["reserved1"])
        
    if pack.name == "Link Local Multicast Node Resolution - Query":
        print(pack.fields["id"])
        print(pack.fields["qr"])
        print(pack.fields["opcode"])
        print(pack.fields["c"])
        print(pack.fields["tc"])
        print(pack.fields["z"])
        print(pack.fields["rcode"])
        print(pack.fields["qdcount"])
        print(pack.fields["ancount"])
        print(pack.fields["nscount"])
        print(pack.fields["arcount"])
        print(pack.fields["qd"])
        print(pack.fields["an"])
        print(pack.fields["ns"])
        print(pack.fields["ar"])
        
        
    if pack.name == "MGCP":
        print(pack.fields["verb"])
        print(pack.fields["sep1"])
        print(pack.fields["transaction_id"])
        print(pack.fields["sep2"])
        print(pack.fields["endpoint"])
        print(pack.fields["sep3"])
        print(pack.fields["version"])
        print(pack.fields["sep4"])

    if pack.name == "Mobile IP (RFC3344)":
        print(pack.fields["type"])

    if pack.name == "Mobile IP Registration Request (RFC3344)":
        print(pack.fields["flags"])
        print(pack.fields["lifetime"])
        print(pack.fields["homeaddr"])
        print(pack.fields["haaddr"])
        print(pack.fields["coaddr"])
        print(pack.fields["id"])
        
    if pack.name == "Mobile IP Registration Reply (RFC3344)":
        print(pack.fields["code"])
        print(pack.fields["lifetime"])
        print(pack.fields["homeaddr"])
        print(pack.fields["haaddr"])
        print(pack.fields["id"])

    if pack.name == "Mobile IP Tunnel Data Message (RFC3519)":
        print(pack.fields["nexthdr"])
        print(pack.fields["res"])
        
    if pack.name == "NetBIOS datagram service":
        print(pack.fields["type"])
        print(pack.fields["flags"])
        print(pack.fields["id"])
        print(pack.fields["src"])
        print(pack.fields["sport"])
        print(pack.fields["len"])
        print(pack.fields["ofs"])
        print(pack.fields["srcname"])
        print(pack.fields["dstname"])
        
    if pack.name == "NBNS query request":
        print(pack.fields["NAME_TRN_ID"])
        print(pack.fields["FLAGS"])
        print(pack.fields["QDCOUNT"])
        print(pack.fields["ANCOUNT"])
        print(pack.fields["NSCOUNT"])
        print(pack.fields["ARCOUNT"])
        print(pack.fields["QUESTION_NAME"])
        print(pack.fields["SUFFIX"])
        print(pack.fields["NULL"])
        print(pack.fields["QUESTION_TYPE"])
        print(pack.fields["QUESTION_CLASS"])
        
    if pack.name == "NBNS request":
        print(pack.fields["NAME_TRN_ID"])
        print(pack.fields["FLAGS"])
        print(pack.fields["QDCOUNT"])
        print(pack.fields["ANCOUNT"])
        print(pack.fields["NSCOUNT"])
        print(pack.fields["ARCOUNT"])
        print(pack.fields["QUESTION_NAME"])
        print(pack.fields["SUFFIX"])
        print(pack.fields["NULL"])
        print(pack.fields["QUESTION_TYPE"])
        print(pack.fields["QUESTION_CLASS"])
        print(pack.fields["RR_NAME"])
        print(pack.fields["RR_TYPE"])
        print(pack.fields["RR_CLASS"])
        print(pack.fields["TTL"])
        print(pack.fields["RDLENGTH"])
        print(pack.fields["G"])
        print(pack.fields["OWNER_NODE_TYPE"])
        print(pack.fields["UNUSED"])
        print(pack.fields["NB_ADDRESS"])

    if pack.name == "NBNS query response":
        print(pack.fields["NAME_TRN_ID"])
        print(pack.fields["FLAGS"])
        print(pack.fields["QDCOUNT"])
        print(pack.fields["ANCOUNT"])
        print(pack.fields["NSCOUNT"])
        print(pack.fields["ARCOUNT"])
        print(pack.fields["RR_NAME"])
        print(pack.fields["SUFFIX"])
        print(pack.fields["NULL"])
        print(pack.fields["QUESTION_TYPE"])
        print(pack.fields["QUESTION_CLASS"])
        print(pack.fields["TTL"])
        print(pack.fields["RDLENGTH"])
        print(pack.fields["RR_CLASS"])
        print(pack.fields["TTL"])
        print(pack.fields["RDLENGTH"])
        print(pack.fields["NB_FLAGS"])
        print(pack.fields["NB_ADDRESS"])
        


    
    if pack.name == "IP":
        print(pack.fields["src"])
        print(pack.fields["dst"])
        print(pack.fields["version"])
        print(pack.fields["ihl"])
        print(pack.fields["tos"])
        print(pack.fields["len"])
        print(pack.fields["id"])
        print(pack.fields["flags"])
        print(pack.fields["frag"])
        print(pack.fields["ttl"])
        print(pack.fields["proto"])
        print(pack.fields["chksum"])
        print(pack.fields["ttl"])
        print(pack.fields["proto"])
        print(pack.fields["options"])
        
    if pack.name == "IP Option Loose Source and Record Route":
        print(pack.fields["length"])
        print(pack.fields["pointer"])
        print(pack.fields["routers"])

    if pack.name == "IP Option Stream ID":
        print(pack.fields["length"])
        print(pack.fields["security"])
        
    if pack.name == "IP Option MTU Probe":
        print(pack.fields["length"])
        print(pack.fields["mtu"])
        
    if pack.name == "IP Option Address Extension":
        print(pack.fields["length"])
        print(pack.fields["src_ext"])
        print(pack.fields["dst_ext"])
        
        
    if pack.name == "IP Option Router Alert":
        print(pack.fields["length"])
        print(pack.fields["alert"])
        
    if pack.name == "IP Option Selective Directed Broadcast Mode":
        print(pack.fields["length"])
        print(pack.fields["addresses"])
        
    
    if pack.name == "TCP":
        print(pack.fields["sport"])
        print(pack.fields["dport"])
        print(pack.fields["seq"])
        print(pack.fields["ack"])
        print(pack.fields["dataofs"])
        print(pack.fields["reserved"])
        print(pack.fields["flags"])
        print(pack.fields["window"])
        print(pack.fields["chksum"])
        print(pack.fields["urgptr"])
        print(pack.fields["options"])

        
    if pack.name == "UDP":
        print(pack.fields["sport"])
        print(pack.fields["dport"])
        print(pack.fields["len"])
        print(pack.fields["chksum"])
        
    if pack.name == "ICMP":
        print(pack.fields["type"])
        print(pack.fields["code"])
        print(pack.fields["chksum"])
        print(pack.fields["id"])
        print(pack.fields["seq"])
        print(pack.fields["ts_ori"])
        print(pack.fields["ts_rx"])
        print(pack.fields["ts_tx"])
        print(pack.fields["gw"])
        print(pack.fields["ptr"])
        print(pack.fields["reserved"])
        print(pack.fields["addr_mask"])
        print(pack.fields["unused"])
        
    if pack.name == "BOOTP":
        print(pack.fields["op"])
        print(pack.fields["htype"])
        print(pack.fields["hlen"])
        print(pack.fields["hops"])
        print(pack.fields["xid"])
        print(pack.fields["secs"])
        print(pack.fields["flags"])
        print(pack.fields["ciaddr"])
        print(pack.fields["yiaddr"])
        print(pack.fields["siaddr"])
        print(pack.fields["giaddr"])
        print(pack.fields["chaddr"])
        print(pack.fields["sname"])
        print(pack.fields["file"])
        print(pack.fields["options"])
        
    if pack.name == "DHCP options":
        print(pack.fields["options"])

    #Bluetooth Protocol
    if pack.name == "HCI header":
        print(pack.fields["type"])
    #Bluetooth Protocol   
    if pack.name == "HCI ACL header":
        print(pack.fields["handle"])
        print(pack.fields["flags"])
        print(pack.fields["len"])
    #Bluetooth Protocol
    if pack.name == "L2CAP header":
        print(pack.fields["len"])
        print(pack.fields["cid"])
    #Bluetooth Protocol
    if pack.name == "L2CAP command header":
        print(pack.fields["code"])
        print(pack.fields["id"])
        print(pack.fields["len"])
    #Bluetooth Protocol
    if pack.name == "L2CAP Conn Req":
        print(pack.fields["psm"])
        print(pack.fields["scid"])
    #Bluetooth Protocol
    if pack.name == "L2CAP Conn Resp":
        print(pack.fields["dcid"])
        print(pack.fields["scid"])
        print(pack.fields["result"])
        print(pack.fields["status"])
    #Bluetooth Protocol
    if pack.name == "L2CAP Command Rej":
        print(pack.fields["reason"])
    #Bluetooth Protocol
    if pack.name == "L2CAP Conf Req":
        print(pack.fields["dcid"])
        print(pack.fields["flags"])
    #Bluetooth Protocol
    if pack.name == "L2CAP Conf Resp":
        print(pack.fields["scid"])
        print(pack.fields["flags"])
        print(pack.fields["result"])
    #Bluetooth Protocol
    if pack.name == "L2CAP Disconn Req":
        print(pack.fields["dcid"])
        print(pack.fields["scid"])
    #Bluetooth Protocol
    if pack.name == "L2CAP Disconn Resp":
        print(pack.fields["dcid"])
        print(pack.fields["scid"])
    #Bluetooth Protocol
    if pack.name == "L2CAP Info Req":
        print(pack.fields["type"])
        print(pack.fields["data"])
    #Bluetooth Protocol
    if pack.name == "L2CAP Info Resp":
        print(pack.fields["type"])
        print(pack.fields["result"])
        print(pack.fields["data"])
        
    if pack.name == "DNS":
        print(pack.fields["id"])
        print(pack.fields["qr"])
        print(pack.fields["opcode"])
        print(pack.fields["aa"])
        print(pack.fields["tc"])
        print(pack.fields["rd"])
        print(pack.fields["ra"])
        print(pack.fields["z"])
        print(pack.fields["rcode"])
        print(pack.fields["qdcount"])
        print(pack.fields["ancount"])
        print(pack.fields["nscount"])
        print(pack.fields["arcount"])
        print(pack.fields["qd"])
        print(pack.fields["an"])
        print(pack.fields["ns"])
        print(pack.fields["ar"])

    if pack.name == "DNS Question Record":
        print(pack.fields["qname"])
        print(pack.fields["qtype"])
        print(pack.fields["qclass"])
        
    if pack.name == "DNS Resource Record":
        print(pack.fields["rrname"])
        print(pack.fields["type"])
        print(pack.fields["rclass"])
        print(pack.fields["ttl"])
        print(pack.fields["rdlen"])
        print(pack.fields["rdata"])
        
    if pack.name == "Prism header":
        print(pack.fields["msgcode"])
        print(pack.fields["len"])
        print(pack.fields["dev"])
        print(pack.fields["hosttime_did"])
        print(pack.fields["hosttime_status"])
        print(pack.fields["hosttime_len"])
        print(pack.fields["hosttime"])
        print(pack.fields["mactime_did"])
        print(pack.fields["mactime_status"])
        print(pack.fields["mactime_len"])
        print(pack.fields["mactime"])
        print(pack.fields["channel_did"])
        print(pack.fields["channel_status"])
        print(pack.fields["channel_len"])
        print(pack.fields["channel"])
        print(pack.fields["rssi_did"])
        print(pack.fields["rssi_status"])
        print(pack.fields["rssi_len"])
        print(pack.fields["rssi"])
        print(pack.fields["sq_did"])
        print(pack.fields["sq_status"])
        print(pack.fields["sq_len"])
        print(pack.fields["sq"])
        print(pack.fields["signal_did"])
        print(pack.fields["signal_status"])
        print(pack.fields["signal_len"])
        print(pack.fields["signal"])
        print(pack.fields["noise_did"])
        print(pack.fields["noise_status"])
        print(pack.fields["noise_len"])
        print(pack.fields["noise"])
        print(pack.fields["rate_did"])
        print(pack.fields["rate_status"])
        print(pack.fields["rate_len"])
        print(pack.fields["rate"])
        print(pack.fields["istx_did"])
        print(pack.fields["istx_status"])
        print(pack.fields["istx_len"])
        print(pack.fields["istx"])
        print(pack.fields["frmlen_did"])
        print(pack.fields["frmlen_status"])
        print(pack.fields["frmlen_len"])
        print(pack.fields["frmlen"])


    if pack.name == "RadioTap dummy":
        print(pack.fields["version"])
        print(pack.fields["pad"])
        print(pack.fields["len"])
        print(pack.fields["present"])
        print(pack.fields["notdecoded"])
        
    if pack.name == "802.11":
        print(pack.fields["subtype"])
        print(pack.fields["type"])
        print(pack.fields["proto"])
        print(pack.fields["FCfield"])
        print(pack.fields["ID"])
        print(pack.fields["addr1"])
        print(pack.fields["addr2"])
        print(pack.fields["addr3"])
        print(pack.fields["SC"])
        print(pack.fields["addr4"])

    if pack.name == "802.11 QoS":
        print(pack.fields["TID"])
        print(pack.fields["EOSP"])
        print(pack.fields["Ack Policy"])
        print(pack.fields["Reserved"])
        print(pack.fields["TXOP"])
        
    if pack.name == "802.11 Beacon":
        print(pack.fields["timestamp"])
        print(pack.fields["beacon_interval"])
        print(pack.fields["cap"])
        
    if pack.name == "802.11 Information Element":
        print(pack.fields["ID"])
        print(pack.fields["len"])
        print(pack.fields["info"])
        
    if pack.name == "802.11 Disassociation":
        print(pack.fields["reason"])

    if pack.name == "802.11 Association Request":
        print(pack.fields["cap"])
        print(pack.fields["listen_interval"])
        
    if pack.name == "802.11 Association Response":
        print(pack.fields["cap"])
        print(pack.fields["status"])
        print(pack.fields["AID"])
        
    if pack.name == "802.11 Reassociation Request":
        print(pack.fields["cap"])
        print(pack.fields["listen_interval"])
        print(pack.fields["current_AP"])
        
    if pack.name == "802.11 Probe Response":
        print(pack.fields["timestamp"])
        print(pack.fields["beacon_interval"])
        print(pack.fields["cap"])
        
    if pack.name == "802.11 Authentication":
        print(pack.fields["algo"])
        print(pack.fields["seqnum"])
        print(pack.fields["status"])
        
        
    if pack.name == "802.11 Deauthentication":
        print(pack.fields["reason"])
        
    if pack.name == "802.11 WEP packet":
        print(pack.fields["iv"])
        print(pack.fields["keyid"])
        print(pack.fields["wepdata"])
        print(pack.fields["icv"])
    
    if pack.name == "GPRSdummy":
        print(pack.fields["dummy"])
        
        
    if pack.name == "HSRP":
        print(pack.fields["version"])
        print(pack.fields["opcode"])
        print(pack.fields["state"])
        print(pack.fields["hellotime"])
        print(pack.fields["holdtime"])
        print(pack.fields["priority"])
        print(pack.fields["group"])
        print(pack.fields["reserved"])
        print(pack.fields["auth"])
        print(pack.fields["virtualIP"])
        
    if pack.name == "IrDA Link Access Protocol Header":
        print(pack.fields["Address"])
        print(pack.fields["Type"])
        
    if pack.name == "IrDA Link Access Protocol Command":
        print(pack.fields["Control"])
        print(pack.fields["Format identifier"])
        print(pack.fields["Source address"])
        print(pack.fields["Destination address"])
        print(pack.fields["Discovery flags"])
        print(pack.fields["Slot number"])
        print(pack.fields["Version"])
        
    if pack.name == "IrDA Link Management Protocol":
        print(pack.fields["Service hints"])
        print(pack.fields["Character set"])
        print(pack.fields["Device name"])

    if pack.name == "ISAKMP":
        print(pack.fields["init_cookie"])
        print(pack.fields["resp_cookie"])
        print(pack.fields["next_payload"])
        print(pack.fields["version"])
        print(pack.fields["exch_type"])
        print(pack.fields["flags"])
        print(pack.fields["id"])
        print(pack.fields["length"])
        
        

        
    
'''
                    #IPField("src", "127.0.0.1"),
                    Emph(SourceIPField("src","dst")),
                    Emph(IPField("dst", "127.0.0.1")),
                    PacketListField("options", [], IPOption, length_from=lambda p:p.ihl*4-20) ]
'''       
        
    
    
print("finished")
    
    
    
    
    
    
    
    
    
    
    
'''
    label_lvl = ""
    lvl = ""
    indent = 3
    ct = conf.color_theme
    print"%s%s %s %s" % (label_lvl, ct.punct("###["), ct.layer_name(pack.name), ct.punct("]###"))
        
    for f in pack.fields_desc:
            if isinstance(f, ConditionalField) and not f._evalcond(pack):
                continue
            if isinstance(f, Emph) or f in conf.emph:
                ncol = ct.emph_field_name
                vcol = ct.emph_field_value
            else:
                ncol = ct.field_name
                vcol = ct.field_value
            fvalue = pack.getfieldval(f.name)
            if isinstance(fvalue, Packet) or (f.islist and f.holds_packets and type(fvalue) is list):
                print "%s  \\%-10s\\" % (label_lvl+lvl, ncol(f.name))
                fvalue_gen = SetGen(fvalue,_iterpacket=0)
                for fvalue in fvalue_gen:
                    fvalue.show(indent=indent, label_lvl=label_lvl+lvl+"   |")
            else:
                print "%s  %-10s%s %s" % (label_lvl+lvl,
                                          ncol(f.name),
                                          ct.punct("="),
                                          vcol(f.i2repr(pack,fvalue)))
'''
    
    
