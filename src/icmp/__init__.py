from enum import Enum
from typing import Callable, Union, TYPE_CHECKING
from ..ip import IPHdr
from ..pkb import Packetbuffer
import struct
from logging import Logger
if TYPE_CHECKING:
    from ..ip.ip import IP

class ICMP_TYPE(Enum):
    ECHORLY = 0
    DESTUNREACH = 3
    ECHOREQ = 8

class ICMPDesc(object):
    def __init__(self, cb: Callable[['IP', 'ICMPDesc', Packetbuffer, Logger], None], error_code: int, info: str) -> None:
        self.cb = cb
        self.error_code = error_code
        self.information = info

class ICMPHdr(object):
    ICMP_HDR_SZIE = 8 + 8 + 16 + 32

    def __init__(self, type: ICMP_TYPE, code: int, checksum: int, data: bytes) -> None:
        self.type = type
        self.code = code
        self.checksum = checksum
        self.data = data

    @classmethod
    def from_bytes(cls, data: bytes) -> Union['ICMPHdr', None]:
        try:
            type, code = struct.unpack("!BB", data[0:2])
            data = data[4:]
            return cls(ICMP_TYPE(type), code, 0, data)
        except:        
            return None

    def to_bytes(self) -> bytes:
        data = struct.pack("!BBH", self.type.value, self.code, 0) + self.data
        self.checksum = IPHdr.checksum(data)
        data = struct.pack("!BBH", self.type.value, self.code, self.checksum) + self.data
        return data
        
class ICMPEchoReply(object):
    def __init__(self, id: int, seq: int, data: bytes) -> None:
        self.id = id
        self.seq = seq
        self.data = data
    
    @classmethod
    def from_bytes(cls, data: bytes) -> Union['ICMPEchoReply', None]:
        try:
            id, seq = struct.unpack("!HH",data[0:4])
            data = data[4:]
            return cls(id, seq, data)
        except:
            return None