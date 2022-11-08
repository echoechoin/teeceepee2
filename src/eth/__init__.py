import re
import random
import struct
from typing import List, Union
from enum import Enum
"""
Ethernet frame format:
  ___________________________________
 | dmac | smac | ethertype | payload |
 |______|______|___________|_________|
 | 6    | 6    | 2         | 0-mtu   |
 |______|______|___________|_________|
"""

class MacAddress():
    MAC_REGEX = re.compile(r'^([0-9a-fA-F]{2}[:]){5}([0-9a-fA-F]{2})$')
    MAC_ADDR_SIZE = 6
    def __init__(self, mac: str = "") -> None:
        if mac == "":
            self._mac = "00:00:00:00:00:00"
            self._mac_bytes = bytes([0x00] * self.MAC_ADDR_SIZE)
        else:
            if not self.MAC_REGEX.match(mac):
                raise ValueError("invalid mac address")
            self._mac = mac
            self._mac_bytes = bytes.fromhex(mac.replace(':', ''))

    def __eq__(self, __o: object) -> bool:
        if not isinstance(__o, MacAddress):
            return False
        return self._mac_bytes == __o._mac_bytes
    
    def __str__(self) -> str:
        return self._mac

    def is_multicast(self) -> bool:
        return self._mac_bytes[0] & 0x01 == 0x01
    
    def is_broadcast(self) -> bool:
        return self._mac_bytes == bytes([0xff] * self.MAC_ADDR_SIZE)
    
    def to_bytes(self) -> bytes:
        return self._mac_bytes

    @classmethod
    def random_mac(cls) -> 'MacAddress':
        mac: List[int] = [0x00, 0x0c, 0x29]
        for _ in range(3):
            mac.append(random.randint(0x00, 0xff))
        return cls.from_bytes(bytes(mac))

    @classmethod
    def from_bytes(cls, mac: bytes) -> 'MacAddress':
        if len(mac) != 6:
            raise ValueError("MacAddress: invalid mac address")
        else:
            return cls(":".join(["{:02x}".format(x) for x in mac]))

class MacAddressType(Enum):
    NONE	  = 0
    LOCALHOST = 1
    OTHERHOST = 2
    MULTICAST = 3
    BROADCAST = 4

class EtherType(Enum):
    IP = 0x0800
    ARP = 0x0806
    RARP = 0x8035
    UNKNOWN = 0xffff

    @classmethod
    def from_bytes(cls, data: bytes) -> 'EtherType':
        try:
            return cls(struct.unpack("!H", data)[0])
        except:
            return cls.UNKNOWN

    def to_bytes(self) -> bytes:
        return struct.pack("!H", self.value)

class EtherHdr():
    ETH_HDR_SIZE = 14
    def __init__(self, dst_hwaddr: MacAddress, src_hwaddr: MacAddress, eth_type: EtherType, data: bytes) -> None:
        self.dst_hwaddr = dst_hwaddr
        self.src_hwaddr = src_hwaddr
        self.eth_type = eth_type
        self.data = data
    
    def to_bytes(self) -> bytes:
        return struct.pack("!6s6s2s", self.dst_hwaddr.to_bytes(), self.src_hwaddr.to_bytes(), self.eth_type.to_bytes()) + self.data

    @classmethod
    def from_bytes(cls, data: bytes) -> Union['EtherHdr', None]:
        try:
            dst_hwaddr = MacAddress.from_bytes(data[0:6])
            src_hwaddr = MacAddress.from_bytes(data[6:12])
            eth_type = EtherType.from_bytes(data[12:14])
            data = data[cls.ETH_HDR_SIZE:]
            return cls(dst_hwaddr, src_hwaddr, eth_type, data)
        except:
            return None
    
    def __str__(self) -> str:
        return "%s -> %s, %s"%(self.src_hwaddr, self.dst_hwaddr, self.eth_type)