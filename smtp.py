import base64
from scapy.packet import *
from scapy.fields import *
from scapy.ansmachine import *
from scapy.layers.inet import *
# holds smtp sessions
bounded = []


def bind(Src, Dst, Port):
    """
    method for creating smtp data sessions
    @param Src: source ip address
    @param Dst: destination ip address
    @param Port: source port number
    """
    bounded.append([Src, Dst, Port])


def unbind(Src, Dst, Port):
    """
    do the opposite of bind()
    """
    if [Src, Dst, Port] in bounded:
        bounded.remove([Src, Dst, Port])


def is_bounded(Src, Dst, Port):
    """
    returns true if the session is already bounded
    @param Src: source ip address
    @param Dst: destination ip address
    @param Port: source port number
    """
    if [Src, Dst, Port] in bounded:
        return True
    return False


class SMTPDataField(XByteField):
    """
    this is a field class for handling the smtp data
    @attention: this class inherets XByteField
    """
    holds_packets = 1
    name = "SMTPDataField"
    myresult = ""

    def __init__(self, name, default):
        """
        class constructor, for initializing instance variables
        @param name: name of the field
        @param default: Scapy has many formats to represent the data
        internal, human and machine. anyways you may sit this param to None.
        """
        self.name = name
        self.fmt = "!B"
        Field.__init__(self, name, default, "!B")

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
        return "", self.myresult


class SMTPResField(StrField):
    """
    this is a field class for handling the smtp data
    @attention: this class inherets StrField
    """
    holds_packets = 1
    name = "SMTPReField"

    def get_code_msg(self, cn):
        """
        method returns a message for every a specific code number
        @param cn: code number
        """
        codes = {
                 "500": "Syntax error, command unrecognized",
                 "501": "Syntax error in parameters or arguments",
                 "502": "Command not implemented",
                 "503": "Bad sequence of commands",
                 "504": "Command parameter not implemented",
                 "211": "System status, or system help reply",
                 "214": "Help message",
                 "220": "<domain> Service ready",
                 "221": "<domain> Service closing transmission channel",
                 "421": "<domain> Service not available,\
                 closing transmission channel",
                 "250": "Requested mail action okay, completed",
                 "251": "User not local; will forward to <forward-path>",
                 "450": "Requested mail action not taken: mailbox unavailable",
                 "550": "Requested action not taken: mailbox unavailable",
                 "451": "Requested action aborted: error in processing",
                 "551": "User not local; please try <forward-path>",
                 "452": "Requested action not taken: insufficient system\
                  storage",
                 "552": "Requested mail action aborted: exceeded storage\
                  allocation",
                 "553": "Requested action not taken: mailbox name not allowed",
                 "354": "Start mail input; end with <CRLF>.<CRLF>",
                 "554": "Transaction failed",
                 "211": "System status, or system help reply",
                 "214": "Help message",
                 "220": "<domain> Service ready",
                 "221": "<domain> Service closing transmission channel",
                 "250": "Requested mail action okay, completed",
                 "251": "User not local; will forward to <forward-path>",
                 "354": "Start mail input; end with <CRLF>.<CRLF>",
                 "421": "<domain> Service not available, closing \
                 transmission channel",
                 "450": "Requested mail action not taken: mailbox unavailable",
                 "451": "Requested action aborted: local error in processing",
                 "452": "Requested action not taken: insufficient system\
                  storage",
                 "500": "Syntax error, command unrecognized",
                 "501": "Syntax error in parameters or arguments",
                 "502": "Command not implemented",
                 "503": "Bad sequence of commands",
                 "504": "Command parameter not implemented",
                 "550": "Requested action not taken: mailbox unavailable",
                 "551": "User not local; please try <forward-path>",
                 "552": "Requested mail action aborted: exceeded storage\
                  allocation",
                 "553": "Requested action not taken: mailbox name not allowed",
                 "554": "Transaction failed"}
        if cn in codes:
            return codes[cn]
        return "Unknown Response Code"

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
        ls = s.splitlines()
        length = len(ls)
        if length == 1:
            value = ls[0]
            arguments = ""
            first = True
            res = value.split(" ")
            for arg in res:
                if not first:
                    arguments = arguments + arg + " "
                first = False
            if "-" in res[0]:
                value = "(" + res[0][:3] + ") " +\
                 self.get_code_msg(res[0][:3]) + " " + res[0][3:]
            else:
                value = "(" + res[0] + ") " + self.get_code_msg(res[0])
            return arguments, value

        if length > 1:
            reponses = []
            for element in ls:
                element = element.split(" ")
                arguments = ""
                first = True
                for arg in element:
                    if not first:
                        arguments = arguments + arg + " "
                    first = False
                if "-" in element[0]:
                    reponses.append(["(" + element[0][:3] + ") " +
                                      self.get_code_msg(element[0][:3]) +
                                       " " + element[0][3:], arguments])
                else:
                    reponses.append(["(" + element[0] + ") " +
                                      self.get_code_msg(element[0]),
                                       arguments])
            return "", reponses
        return "", ""

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


class SMTPReqField(StrField):
    holds_packets = 1
    name = "SMTPReqField"

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
        if ls[0].upper() == "DATA":
            bind(pkt.underlayer.underlayer.fields["src"],
                 pkt.underlayer.underlayer.fields["dst"],
                 pkt.underlayer.fields["sport"])
            return "", "DATA"
        if ls[0].upper() == "QUIT":
            unbind(pkt.underlayer.underlayer.fields["src"],
                   pkt.underlayer.underlayer.fields["dst"],
                   pkt.underlayer.fields["sport"])
            return "", "QUIT"
        if is_bounded(pkt.underlayer.underlayer.fields["src"],
                     pkt.underlayer.underlayer.fields["dst"],
                     pkt.underlayer.fields["sport"]):
            smtpd = SMTPData(s).fields["SMTP Data"]
            return "", ["DATA", smtpd]

        if length > 1:
            value = ls[0]
            if length == 2:
                remain = ls[1]
                return remain, value
            else:
                i = 1
                remain = ' '
                while i < length:
                    remain = remain + ls[i] + ' '
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


class SMTPData(Packet):
    """
    class for handling the smtp data
    @attention: this class inherets Packet
    """
    name = "smtp"
    fields_desc = [SMTPDataField("SMTP Data", "")]


class SMTPResponse(Packet):
    """
    class for handling the smtp responses
    @attention: this class inherets Packet
    """
    name = "smtp"
    fields_desc = [SMTPResField("response", "", "H"),
                    StrField("argument", "", "H")]


class SMTPRequest(Packet):
    """
    class for handling the smtp requests
    @attention: this class inherets Packet
    """
    name = "smtp"
    fields_desc = [SMTPReqField("command", '', "H"),
                    StrField("argument", '', "H")]

bind_layers(TCP, SMTPResponse, sport=25)
bind_layers(TCP, SMTPRequest, dport=25)
bind_layers(TCP, SMTPResponse, sport=587)
bind_layers(TCP, SMTPRequest, dport=587)

"""
pkts = rdpcap("/root/Desktop/smtp.pcap")
for pkt in pkts:
    pkt.show()
"""
