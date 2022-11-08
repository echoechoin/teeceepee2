from enum import Enum
from ipaddress import IPv4Address, IPv4Network
import struct
import socket
from typing import Union

class IPAddress(IPv4Address):
    def __init__(self, address: object) -> None:
        super().__init__(address)

class IPNetwork(IPv4Network):
    def __init__(self, address: object, strict: bool = False) -> None:
        super().__init__(address, strict)

"""
 _____________________________________________________________________________________________________________________________
| ihl | version | tos | length | id | flags | frag_offset | ttl | proto | csum | saddr | daddr | options | data               |
|_____|_________|_____|________|____|_______|_____________|_____|_______|______|_______|_______|_________|____________________|
| 4   | 4       | 8   | 16     | 16 | 16:3  | 16:13       | 8   | 8     | 16   | 32    | 32    | 40bytes | 65535-60bytes      |
|_____|_________|_____|________|____|_______|_____________|_____|_______|______|_______|_______|_________|____________________|
version: class IPProtoVer
tos: class IPTOS
proto: class IPProto
"""

class IPProtoVer(Enum):
    IPV4 = 4
    IPV6 = 6
    UNKNOWN = -1

    @classmethod
    def from_bytes(cls, data: bytes) -> 'IPProtoVer':
        try:
            return cls(struct.unpack("!B", data)[0])
        except:
            return cls.UNKNOWN

    def to_bytes(self) -> bytes:
        return struct.pack("!B", self.value)
 
class IPTOS(Enum):
    IPIOS_ROUTINE = 0b000
    IPIOS_PRIORITY = 0b001
    IPIOS_IMMEDIATE = 0b010
    IPIOS_FLASH = 0b011
    IPIOS_FLASH_OVERRIDE = 0b100
    IPIOS_CRITIC = 0b101
    IPIOS_INETCONTROL = 0b110
    IPIOS_NETCONTROL = 0b111
    UNKNOWN = -1

    @classmethod
    def from_bytes(cls, data: bytes) -> 'IPTOS':
        try:
            return cls(struct.unpack("!B", data)[0])
        except:
            return cls.UNKNOWN

    def to_bytes(self) -> bytes:
        return struct.pack("!B", self.value)


class IPProto(Enum):
    ICMP = 1
    TCP = 6
    UDP = 17
    RAW = 255
    UNKNOWN = -1
    @classmethod
    def from_bytes(cls, data: bytes) -> 'IPProto':
        try:
            return cls(struct.unpack("!B", data)[0])
        except:
            return cls.UNKNOWN
    
    def to_bytes(self) -> bytes:
        return struct.pack("!B", self.value)


class IPHdr(object):

    IP_HDR_SIZE = 20

    def __init__(self, hdr_len:int, version: IPProtoVer, tos: IPTOS, total_len: int, id: int, dont_frag: bool, more_frag: bool, frag_off: int, ttl: int, proto: IPProto, src_ipaddr: IPAddress, dst_ipaddr: IPAddress, options: bytes, data: bytes, cksum:int = 0) -> None:
        self.hdr_len = hdr_len
        self.version = version
        self.tos = tos
        self.total_len = total_len
        self.id = id
        self.dont_frag = dont_frag
        self.more_frag = more_frag
        self.frag_off = frag_off
        self.ttl = ttl
        self.proto = proto
        self.cksum = 0
        self.src_ipaddr = src_ipaddr
        self.dst_ipaddr = dst_ipaddr
        self.options = options
        self.data = data
    
    @classmethod
    def checksum(cls, data:bytes) -> int:
        if len(data) < 2:
            return 0
        if len(data) % 2 == 1:
            data += b'\x00'
        sum = 0
        for i in range(0, len(data), 2):
            sum += struct.unpack("!H", data[i:i+2])[0]
            if sum > 0xffff:
                sum = (sum & 0xffff) + 1
        return sum ^ 0xffff
    
    @classmethod
    def from_bytes(cls, data: bytes) -> Union['IPHdr', None]:
        try:
            data_array = bytearray(data)
            hdr_len = (data_array[0] & 0x0f) * 32 // 8
            version = IPProtoVer.from_bytes((data_array[0] >> 4).to_bytes(1, 'big'))
            tos = IPTOS.from_bytes(data[1:2])
            total_len = struct.unpack("!H", data[2:4])[0]
            id = struct.unpack("!H", data[4:6])[0]
            dont_frag = (data_array[6] & 0x40) >> 6 == 1
            more_frag = (data_array[6] & 0x20) >> 5 == 1
            # 偏移值左移3位才是真正的偏移
            frag_off = (struct.unpack("!H", data[6:8])[0] & 0x1fff) * 8
            ttl = data[8]
            proto = IPProto.from_bytes(data[9:10])
            cksum = struct.unpack("!H", data[10:12])[0]
            src_ipaddr = IPAddress(struct.unpack("!I", data[12:16])[0])
            dst_ipaddr = IPAddress(struct.unpack("!I", data[16:20])[0])
            options = data[cls.IP_HDR_SIZE: hdr_len - cls.IP_HDR_SIZE]
            data = data[hdr_len:]
            return cls(hdr_len, version, tos, total_len, id, dont_frag, more_frag, frag_off, ttl, proto, src_ipaddr, dst_ipaddr, options, data, cksum)
        except:
            return None

    def to_bytes(self) -> bytes:
        hlen_verson = struct.pack("!B", (self.hdr_len * 8 // 32) + (self.version.value << 4))
        tos = struct.pack("!B", self.tos.value)
        total_len = struct.pack("!H", self.total_len)
        id = struct.pack("!H", self.id)
        dont_frag =  0x40 if self.dont_frag else 0x00
        more_frag = 0x20 if self.more_frag else 0x00
        frag_off = struct.pack("!H", self.frag_off + (dont_frag << 8) + (more_frag << 8))
        ttl = struct.pack("!B", self.ttl)
        proto = struct.pack("!B", self.proto.value)
        checksum = b"\x00\x00"
        src_ip = socket.inet_aton(str(self.src_ipaddr))
        dst_ip = socket.inet_aton(str(self.dst_ipaddr))
        options = self.options
        data = hlen_verson + tos + total_len \
            + id + frag_off + ttl + proto + checksum + src_ip + dst_ip + options
        cksum = self.checksum(data)
        checksum = struct.pack("!H", cksum)
        return hlen_verson + tos + total_len \
            + id + frag_off + ttl + proto + checksum + src_ip + dst_ip + options + self.data
    
    def __str__(self) -> str:
        s = ""
        s += "IP Header Info:\n"
        s += "Version: {}\n".format(self.version)
        s += "Header Length: {}\n".format(self.hdr_len)
        s += "TOS: {}\n".format(self.tos)
        s += "Total Length: {}\n".format(self.total_len)
        s += "ID: {}\n".format(self.id)
        s += "Don't Fragment: {}\n".format(self.dont_frag)
        s += "More Fragment: {}\n".format(self.more_frag)
        s += "Fragment Offset: {}\n".format(self.frag_off)
        s += "TTL: {}\n".format(self.ttl)
        s += "Protocol: {}\n".format(self.proto)
        s += "Checksum: {}\n".format(self.cksum)
        s += "Source IP: {}\n".format(self.src_ipaddr)
        s += "Destination IP: {}\n".format(self.dst_ipaddr)
        return s