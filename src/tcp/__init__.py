import struct
from typing import Union
from ..ip import IPAddress, IPHdr, IPProto
from enum import Enum

class TCPState(Enum):
    CLOSED = 1
    LISTEN = 2
    SYN_RECV = 3
    SYN_SENT = 4
    ESTABLISHED = 5
    CLOSE_WAIT = 6
    LAST_ACK = 7
    FIN_WAIT1 = 8
    FIN_WAIT2 = 9
    CLOSING = 10
    TIME_WAIT = 11
    MAX_STATE = 12

"""
TCP header(unit: bits) 大端（网络）字节序
  _____________________________________________________________________________________________________________________________________________
 |  sport    | dport    | seq   | ack_seq | hl   | rsvd | fin  | syn  | rst  | psh  | ack  | urg | ece | cwr | win   | csun  | urp  | options  |
 |___________|__________|_______|_________|______|______|______|______|______|______|______|_____|_____|_____|_______|_______|______|__________|
 | 16bits    | 16bits   | 32bits| 32bits  | 4bits| 4bits| 1bit | 1bit | 1bit | 1bit | 1bit | 1bit| 1bit| 1bit| 16bits| 16bits|16bits| 0-40bytes|
 |___________|__________|_______|_________|______|______|______|______|______|______|______|_____|_____|_____|_______|_______|______|__________|
"""

class TCPHdr(object):
    TCP_HDR_LEN = 20
    TCP_DEFAULT_TTL = 64
    def __init__(self,
        src_port: int = 0, dst_port: int = 0, seqn: int = 0,ackn: int = 0, data_offset: int = 0, # tcp头部长度
        cwr: bool = False, ece: bool = False, urg: bool = False, ack: bool = False, psh: bool = False, rst: bool = False, syn: bool = False, fin: bool = False,
        window: int = 0, checksum: int = 0, # tcp头部校验和
        urgptr: int = 0, options: bytes = b'', data: bytes = b'',
        ) -> None:
        self.src_port = src_port
        self.dst_port = dst_port
        self.seqn = seqn
        self.ackn = ackn
        self.data_offset = data_offset
        self.cwr = cwr
        self.ece = ece
        self.urg = urg
        self.ack = ack
        self.psh = psh
        self.rst = rst
        self.syn = syn
        self.fin = fin
        self.window = window
        self.checksum = checksum
        self.urgptr = urgptr
        self.options = options
        self.data = data

    """
    TCP Pseudo Header:(用于计算校验和)
     ________________________________________________
    |  src_addr | dst_addr | zero  | proto | tcp_len |
    |___________|__________|_______|_______|_________|
    | 32bits    | 32bits   | 8bits | 8bits | 16bits  |
    |___________|__________|_______|_______|_________|
    """
    @staticmethod
    def tcp_hdr_checksum(data: bytes, src_ipaddr: IPAddress, dst_ipaddr: IPAddress) -> int:
        tcp_presudo_hdr = struct.pack("!IIBBH", int(src_ipaddr), int(dst_ipaddr), 0, IPProto.TCP.value, len(data))
        tcp_presudo_hdr += data
        return IPHdr.checksum(tcp_presudo_hdr)
    

    @classmethod
    def from_bytes(cls, data: bytes) -> Union['TCPHdr', None]:
        try:
            src_port, dst_port, seqn, ackn, \
            doff, flags, window, checksum, urgptr = struct.unpack("!HHLLBBHHH", data[:cls.TCP_HDR_LEN])
            data_offset = (doff >> 4) * 4
            cwr = True if flags & 0b10000000 == 0b10000000 else False
            ece = True if flags & 0b01000000 == 0b01000000 else False
            urg = True if flags & 0b00100000 == 0b00100000 else False
            ack = True if flags & 0b00010000 == 0b00010000 else False
            psh = True if flags & 0b00001000 == 0b00001000 else False
            rst = True if flags & 0b00000100 == 0b00000100 else False
            syn = True if flags & 0b00000010 == 0b00000010 else False
            fin = True if flags & 0b00000001 == 0b00000001 else False
            option = data[cls.TCP_HDR_LEN:data_offset]
            data = data[data_offset:]
            return cls(src_port, dst_port, seqn, ackn, data_offset, cwr, ece, urg, ack, psh, rst, syn, fin, window, checksum, urgptr, option, data)
        except:
            return None

    def to_bytes(self, src_ipaddr: IPAddress, dst_ipaddr: IPAddress) -> bytes:
        flags = 0
        if self.cwr:
            flags |= 0b10000000
        if self.ece:
            flags |= 0b01000000
        if self.urg:
            flags |= 0b00100000
        if self.ack:
            flags |= 0b00010000
        if self.psh:
            flags |= 0b00001000
        if self.rst:
            flags |= 0b00000100
        if self.syn:
            flags |= 0b00000010
        if self.fin:
            flags |= 0b00000001
        data_offset = (self.data_offset // 4) << 4
        data =  struct.pack("!HHIIBBHHH", self.src_port, self.dst_port, self.seqn, self.ackn, \
            data_offset, flags, self.window, 0, self.urgptr) + self.options + self.data

        checksum = self.tcp_hdr_checksum(data, src_ipaddr, dst_ipaddr)
        return struct.pack("!HHIIBBHHH", self.src_port, self.dst_port, self.seqn, self.ackn, \
            data_offset, flags, self.window, checksum, self.urgptr) + self.options + self.data

    def __str__(self) -> str:
        s = ""
        s += "src_port: %d dst_port: %d seqn: %d ackn: %d data_offset: %d " % (self.src_port, self.dst_port, self.seqn, self.ackn, self.data_offset)
        s += "cwr: %d ece: %d urg: %d ack: %d psh: %d rst: %d syn: %d fin: %d " % (self.cwr, self.ece, self.urg, self.ack, self.psh, self.rst, self.syn, self.fin)
        s += "window: %d checksum: %d urgptr: %d " % (self.window, self.checksum, self.urgptr)
        return s

    def get_flags(self) -> str:
        flags = ""
        if self.syn:
            flags += "SYN, "
        if self.fin:
            flags += "FIN, "
        if self.psh:
            flags += "PSH, "
        if self.rst:
            flags += "RST, "
        if self.cwr:
            flags += "CWR, "
        if self.ece:
            flags += "ECE, "
        if self.urg:
            flags += "URG, "
        if self.ack:
            flags += "ACK, "
        return flags[:-2]