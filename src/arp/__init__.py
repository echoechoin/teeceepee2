from enum import Enum
from typing import Union
from ..eth import EtherType, MacAddress
from ..ip import IPAddress
import socket
import struct


"""
ARP packet format:
 __________________________________________________________________________________________________________________
| hwtype | protype | hwsize | protosize | opcode | sndr_hwaddr | sndr_protoaddr | target_hwaddr | target_protoaddr |
|________|_________|________|___________|________|_____________|________________|_______________|__________________|
| 1      | 1       | 1      | 1         | 1      | 0-6         | 0-4            | 0-6           | 0-4              |
|________|_________|________|___________|________|_____________|________________|_______________|__________________|
hwtype: HardwareType
protype: class EtherType
"""

class HardwareType(Enum):
    ETHERNET = 1
    UNKNOWN = -1

    @classmethod
    def from_bytes(cls, data :bytes) -> 'HardwareType':
        try:
            return cls(struct.unpack("!H", data[:2])[0])
        except:
            return cls.UNKNOWN

class ArpOPCode(Enum):
    ARP_REQUEST = 1
    ARP_REPLY   = 2
    RARP_REQUEST = 3
    RARP_REPLY = 4
    UNKNOWN = -1

    @classmethod
    def from_bytes(cls, data: bytes) -> 'ArpOPCode':
        if len(data) != 2:
            raise ValueError("invalid arp op code")
        opcode = struct.unpack("!H", data[:2])[0]
        try:
            return cls(opcode)
        except ValueError:
            return cls.UNKNOWN
    
    def to_bytes(self) -> bytes:
        return struct.pack("!H", self.value)

class ArpHdr(object):
    ARP_HDR_SIZE = 8
    def __init__(self, hwtype:HardwareType, protype: EtherType, hwsize: int, protosize: int, opcode: ArpOPCode, data: bytes) -> None:
        self.hwtype = hwtype
        self.protype = protype
        self.hwsize = hwsize
        self.protosize = protosize
        self.opcode = opcode
        self.data = data

    def to_bytes(self) -> bytes:
        return struct.pack('!HHBBH', self.hwtype.value, self.protype.value, self.hwsize, self.protosize, self.opcode.value) + self.data

    @classmethod
    def from_bytes(cls,data: bytes) -> Union['ArpHdr', None]:
        try:
            hwtype = HardwareType.from_bytes(data[:2])
            protype = EtherType.from_bytes(data[2:4])
            hwsize = struct.unpack('!B', data[4:5])[0]
            protosize = struct.unpack('!B', data[5:6])[0]
            opcode = ArpOPCode(struct.unpack('!H', data[6:8])[0])
            data = data[8:]
            return cls(hwtype, protype, hwsize, protosize, opcode, data)
        except:
            return None

class ArpIpHdr(object):
    ARP_IPV4_HDR_SIZE = 20
    def __init__(self, src_hwaddr: MacAddress, src_ipaddr: IPAddress, dst_hwaddr: MacAddress, dst_ipaddr: IPAddress) -> None:
        self.src_hwaddr = src_hwaddr
        self.src_ipaddr = src_ipaddr
        self.dst_hwaddr = dst_hwaddr
        self.dst_ipaddr = dst_ipaddr
    
    def to_bytes(self) -> bytes:
        return struct.pack(
            "!6s4s6s4s", 
            self.src_hwaddr.to_bytes(),
            socket.inet_aton(str(self.src_ipaddr)),
            self.dst_hwaddr.to_bytes(),
            socket.inet_aton(str(self.dst_ipaddr))
        )
    
    @classmethod
    def from_bytes(cls, data :bytes) -> Union['ArpIpHdr', None]:
        try:
            src_hwaddr = MacAddress.from_bytes(data[:6])
            src_ipaddr = IPAddress(socket.inet_ntoa(data[6:10]))
            dst_hwaddr = MacAddress.from_bytes(data[10:16])
            dst_ipaddr = IPAddress(socket.inet_ntoa(data[16:20]))
            return cls(src_hwaddr, src_ipaddr, dst_hwaddr, dst_ipaddr)
        except:
            return None