
from ..ip import IPAddress
from typing import Union, TYPE_CHECKING
from abc import ABC, abstractmethod
from ..eth import MacAddress
from ..pkb import Packetbuffer
from logging import DEBUG
from ..ip import IPHdr
from ..eth import EtherHdr
if TYPE_CHECKING:
    from ..netdev.dev_manager import NetDeviceManageThread
    from ..logger_manager import Logger

class NetDeviceStatus(object):
    def __init__(self) -> None:
        self.rx_packets = 0
        self.tx_packets = 0
        self.rx_errors = 0
        self.tx_errors = 0
        self.rx_bytes = 0
        self.tx_bytes = 0
        

class NetDevice(ABC):
    def __init__(self, name: str, logger_manager: 'Logger') -> None:
        self.mtu: int = 1500
        self.ipaddr: Union[IPAddress, None] = None
        self.mask: int = 32
        self.hwaddr: MacAddress = MacAddress.random_mac()
        self.name: str = name
        self.netstats: NetDeviceStatus = NetDeviceStatus()
        self.netdev_manager: Union['NetDeviceManageThread', None] = None
        self.logger = logger_manager.get_logger("netdev")
    
    def debug(self, pkb: Packetbuffer, send: bool = True) -> None:
        try:
            if self.logger.level == DEBUG:
                eth_hdr = EtherHdr.from_bytes(pkb.data)
                assert eth_hdr is not None
                src_hwaddr = eth_hdr.src_hwaddr
                dst_hwaddr = eth_hdr.dst_hwaddr
                if send:
                    self.logger.debug("send: src_mac=%s, dst_mac=%s" % (src_hwaddr, dst_hwaddr))
                else:
                    self.logger.debug("recv: src_mac=%s, dst_mac=%s" % (src_hwaddr, dst_hwaddr))
        except:
            self.logger.warning("debug: %s error" % pkb)

    @abstractmethod
    def send(self, pkb: Packetbuffer) -> int:
        return 0

    @abstractmethod
    def recv(self, pkb: Packetbuffer) -> Union[Packetbuffer, None]:
        return pkb

    @abstractmethod
    def change_ip_address(self, ipaddress: IPAddress, mask: int) -> None:
        raise NotImplementedError

    @abstractmethod
    def change_mac_address(self, mac: MacAddress) -> None:
        if self.netdev_manager != None:
            # 判断mac地址是否已经被使用
            for dev in self.netdev_manager.veth_devices:
                if dev.hwaddr == mac:
                    raise ValueError("mac address already used")
            if self.netdev_manager.loop_device.hwaddr == mac:
                raise ValueError("mac address already used")
        self.hwaddr = mac
            

    @abstractmethod
    def exit(self) -> None:
        pass
