'''
This is a Tiny program which aim to dissect any predefined protocol supported by Scapy
the program extract the packets from a pcap file and dissect every packet in the file
'''
from scapy.all import Packet,rdpcap,ConditionalField,Emph,conf

packetslist = rdpcap("/root/Desktop/dump.cap")

def dissect(self,indent=3,label_lvl="",lvl=""):
    ct = conf.color_theme
    flds = []
    flds.append(ct.layer_name(self.name))

    for f in self.fields_desc:
            if isinstance(f, ConditionalField) and not f._evalcond(self):
                continue
            if isinstance(f, Emph) or f in conf.emph:
                ncol = ct.emph_field_name
                vcol = ct.emph_field_value
            else:
                ncol = ct.field_name
                vcol = ct.field_value
                
            fvalue = self.getfieldval(f.name)
            if isinstance(fvalue, Packet) or (f.islist and f.holds_packets and type(fvalue) is list):
                flds.append((label_lvl +lvl, ncol(f.name)))
            else:
                flds.append((( ncol(f.name), vcol(f.i2repr(self,fvalue)))))
    return flds


for pkt in packetslist :
    firstlayer= True
    if pkt :
        print("=========={ New Packet }==========")
        load = pkt
        while load.payload != None :
            if firstlayer :
                fields = dissect(pkt)
                firstlayer = False
            else :
                load = load.payload
                fields = dissect(load)
            
            if fields[0] :
                if fields[0] == "NoPayload" :
                    break
                print("-----[ " + fields[0] + " ]-----")
                
            for fld in fields :
                    if len(fld)==2 :
                        print("%s = %s" % (fld[0],fld[1]))
