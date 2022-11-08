from enum import Enum
from ..ip import IPAddress
from typing import Union
from ..netdev.dev import NetDevice
from ..eth import MacAddress, EtherType
from ..pkb import PKBQueue

class ArpEntryState(Enum):
    WAITING = 0
    RESOLVED = 1
    STATIC  = 2
    NONE    = 3

class ArpEntry(object):
    MAX_RETRY_TIMES = 5
    MAX_PEIDING_PACKETS = 8192
    MAX_TTL = 60 * 10
    def __init__(self, ipaddr: IPAddress, hwaddr: Union[MacAddress, None], 
                netdev: NetDevice, retry_count: int = 0,
                ttl: int = MAX_TTL, state: ArpEntryState = ArpEntryState.RESOLVED,
                proto: EtherType = EtherType.IP) -> None:
        self.pending_packets = PKBQueue(self.MAX_PEIDING_PACKETS)
        self.netdev = netdev
        self.retry_count = retry_count
        self.ttl = ttl
        self.state = state
        self.proto = proto
        self.ipaddr = ipaddr
        self.hwaddr = hwaddr