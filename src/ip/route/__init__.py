from enum import Enum
from typing import Union
from ...netdev.dev import NetDevice
from ...ip import IPAddress, IPNetwork

class RouteFlags(Enum):
    NONE = 0
    LOCALHOST = 1
    DEFAULT = 2

class RouteEntry(object):
    def __init__(self, net: IPNetwork, gateway: Union[IPAddress, None], flags: RouteFlags, metric:int, netdev: NetDevice) -> None:
        self.net: IPNetwork = net
        self.gateway: Union[IPAddress, None] = gateway
        self.flags: RouteFlags = flags
        self.metric: int = metric
        self.netdev: NetDevice = netdev # output net device or local net device