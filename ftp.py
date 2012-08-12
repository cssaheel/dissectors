import base64
from scapy.packet import *
from scapy.fields import *
from scapy.ansmachine import *
from scapy.layers.inet import *

# list for maintaining  the ftp data sessions
ftpdatasessions = []


def is_created_session(Src, Dst, SPort):
    """
    this method returns true if the ftp data session is exist
    @param Src: source ip address
    @param Dst: destination ip address
    @param SPort: source port number
    """
    i = 0
    while i < len(ftpdatasessions):
        if  str(Src) and str(Dst) and str(SPort) in ftpdatasessions[i]:
            return True
        i = i + 1
    return False


def create_session(Src, Dst, SPort):
    """
    this method for creating the ftp data sessions
    @param Src: source ip address
    @param Dst: destination ip address
    @param SPort: source port number
    """
    if not is_created_session(Src, Dst, SPort):
        ftpdatasessions.append([Src, Dst, SPort])
        return True
    return False


def bind(Port):
    """
    ftp data sessions which get establish after do an agreement
    on a specific port number at the server, this port number need
    to be bounded by using bind_layers() method
    @param Port: source port number at the server side
    """
    bind_layers(TCP, FTPData, sport=int(Port))


class FTPDataField(XByteField):
    """
    this is a field class for handling the ftp data
    @attention: this class inherets XByteField
    """
    holds_packets = 1
    name = "FtpDataField"
    myresult = ""

    def __init__(self, name, default):
        """
        FTPDataField constructor, for initializing instance variables
        @param name: name of the field
        @param default: Scapy has many formats to represent the data
        internal, human and machine. anyways you may sit this param to None.
        """
        self.name = name
        self.fmt = "!B"
        Field.__init__(self, name, default, "!B")

    def getfield(self, pkt, s):
        self.myresult = ""
        firstb = struct.unpack(self.fmt, s[0])[0]
        self.myresult = ""
        for c in s:
            ustruct = struct.unpack(self.fmt, c)
            byte = base64.standard_b64encode(str(ustruct[0]))
            '''
            byte = str(hex(ustruct[0]))[2:]
            if len(byte) == 1:
                byte = "0" + byte
            '''
            self.myresult = self.myresult + c
        if not is_created_session(pkt.underlayer.underlayer.fields["src"],
                                pkt.underlayer.underlayer.fields["dst"],
                                pkt.underlayer.fields["sport"]):
            return self.myresult, ""
        return "", self.myresult


class FTPResArgField(StrField):
    """
    class field to handle the ftp responses' arguments
    @attention: it inherets StrField which is imported from Scapy
    """
    holds_packets = 1
    name = "FTPResArgField"

    def getfield(self, pkt, s):
        """
        this method will get the packet, takes what does need to be
        taken and let the remaining go, so it returns two values.
        first value which belongs to this field and the second is
        the remaining which does need to be dissected with
        other "field classes".
        @param pkt: holds the whole packet
        @param s: holds only the remaining data which is not dissected yet.
        """
        value = ""
        if "Entering Passive Mode (" in s:
            value = []
            res = s.split("Entering Passive Mode (")
            res.remove(res[0])
            res = res[0].split(").")
            del(res[len(res)-1])
            res = res[0].split(",")
            IP = res[0] + "." + res[1] + "." + res[2] + "." + res[3]
            Port = str(int(res[4]) * 256 + int(res[5]))
            value.append(("Passive IP Address", IP))
            value.append(("Passive Port Number", Port))
            if(create_session(IP, pkt.underlayer.underlayer.fields["dst"],
                              Port)):
                bind(Port)
            return "", value
        else:
            value = s
            return "", value

    def __init__(self, name, default, fmt, remain=0):
        """
        FTPResArgField constructor for initializing the instance variables
        @param name: name of the field
        @param default: Scapy has many formats to represent the data
        internal, human and machine. anyways you may sit this param to None.
        @param fmt: specifying the format, this has been set to "H"
        @param remain: this parameter specifies the size of the remaining
        data so make it 0 to handle all of the data.
        """
        self.name = name
        StrField.__init__(self, name, default, fmt, remain)


class FTPResField(StrField):
    """
    class field to handle the ftp responses
    @attention: it inherets StrField which is imported from Scapy
    """
    holds_packets = 1
    name = "FTPReField"

    def get_code_msg(self, cn):
        """
        method which returns message for a ftp code number
        @param cn: code number
        """
        codes = {
    "110": "Restart marker reply",
    "120": "Service ready in nnn minutes",
    "125": "Data connection already open; transfer starting",
    "150": "File status okay; about to open data connection",
    "200": "Command okay",
    "202": "Command not implemented, superfluous at this site",
    "211": "System status, or system help reply",
    "212": "Directory status",
    "213": "File status",
    "214": "Help message",
    "215": "NAME system type",
    "220": "Service ready for new user",
    "221": "Service closing control connection",
    "225": "Data connection open; no transfer in progress",
    "226": "Closing data connection",
    "227": "Entering Passive Mode",
    "230": "User logged in proceed",
    "250": "Requested file action okay completed",
    "257": "PATHNAME created",
    "331": "User name okay need password",
    "332": "Need account for login",
    "350": "Requested file action pending further information",
    "421": "Service not available closing control connection",
    "425": "Can't open data connection",
    "426": "Connection closed; transfer aborted",
    "450": "Requested file action not taken",
    "451": "Requested action aborted: local error in processing",
    "452": "Requested action not taken. Insufficient storage space in system",
    "500": "Syntax error command unrecognized",
    "501": "Syntax error in parameters or arguments",
    "502": "Command not implemented",
    "503": "Bad sequence of commands",
    "504": "Command not implemented for that parameter",
    "530": "Not logged in",
    "532": "Need account for storing files",
    "550": "Requested action not taken: File unavailable",
    "551": "Requested action aborted: page type unknown",
    "552": "Requested file action aborted: Exceeded storage allocation",
    "553": "Requested action not taken: File name not allowed",
 }
        if cn in codes:
            return codes[cn]
        return ""

    def getfield(self, pkt, s):
        """
        this method will get the packet, takes what does need to be
        taken and let the remaining go, so it returns two values.
        first value which belongs to this field and the second is
        the remaining which does need to be dissected with
        other "field classes".
        @param pkt: holds the whole packet
        @param s: holds only the remaining data which is not dissected yet.
        """
        remain = ""
        value = ""
        ls = s.split()
        length = len(ls)
        if length > 1:
            value = self.get_code_msg(ls[0]) + " (" + ls[0] + ")"
            if length == 2:
                remain = ls[1]
                return remain, value
            else:
                i = 1
                remain = ""
                while i < length:
                    if i != 1:
                        remain = remain + " " + ls[i]
                    elif i == 1:
                        remain = remain + ls[i]
                    i = i + 1
                return remain, value
        else:
            return "", self.get_code_msg(ls[0]) + " (" + ls[0] + ")"

    def __init__(self, name, default, fmt, remain=0):
        """
        class constructor for initializing the instance variables
        @param name: name of the field
        @param default: Scapy has many formats to represent the data
        internal, human and machine. anyways you may sit this param to None.
        @param fmt: specifying the format, this has been set to "H"
        @param remain: this parameter specifies the size of the remaining
        data so make it 0 to handle all of the data.
        """
        self.name = name
        StrField.__init__(self, name, default, fmt, remain)


class FTPReqField(StrField):
    holds_packets = 1
    name = "FTPReqField"

    def getfield(self, pkt, s):
        """
        this method will get the packet, takes what does need to be
        taken and let the remaining go, so it returns two values.
        first value which belongs to this field and the second is
        the remaining which does need to be dissected with
        other "field classes".
        @param pkt: holds the whole packet
        @param s: holds only the remaining data which is not dissected yet.
        """
        remain = ""
        value = ""
        ls = s.split()
        length = len(ls)
        if length > 1:
            value = ls[0]
            if length == 2:
                remain = ls[1]
                return remain, value
            else:
                i = 1
                remain = ""
                while i < length:
                    remain = remain + ls[i] + " "
                    i = i + 1
                return remain, value
        else:
            return "", ls[0]

    def __init__(self, name, default, fmt, remain=0):
        """
        class constructor for initializing the instance variables
        @param name: name of the field
        @param default: Scapy has many formats to represent the data
        internal, human and machine. anyways you may sit this param to None.
        @param fmt: specifying the format, this has been set to "H"
        @param remain: this parameter specifies the size of the remaining
        data so make it 0 to handle all of the data.
        """
        self.name = name
        StrField.__init__(self, name, default, fmt, remain)


class FTPData(Packet):
    """
    class for dissecting the ftp data
    @attention: it inherets Packet class from Scapy library
    """
    name = "ftp"
    fields_desc = [FTPDataField("data", "")]


class FTPResponse(Packet):
    """
    class for dissecting the ftp responses
    @attention: it inherets Packet class from Scapy library
    """
    name = "ftp"
    fields_desc = [FTPResField("command", "", "H"),
                    FTPResArgField("argument", "", "H")]


class FTPRequest(Packet):
    """
    class for dissecting the ftp requests
    @attention: it inherets Packet class from Scapy library
    """
    name = "ftp"
    fields_desc = [FTPReqField("command", "", "H"),
                    StrField("argument", "", "H")]

bind_layers(TCP, FTPResponse, sport=21)
bind_layers(TCP, FTPRequest, dport=21)
bind_layers(TCP, FTPData, dport=20)
bind_layers(TCP, FTPData, dport=20)
"""
pkts = rdpcap("/root/Desktop/ftp.cap")

for pkt in pkts:
    pkt.show()
"""
