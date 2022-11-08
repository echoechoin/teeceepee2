from ..ip import IPAddress
from typing import Union, TYPE_CHECKING
from .dev import NetDevice
from ..pkb import Packetbuffer
from ..eth import MacAddress
if TYPE_CHECKING:
    from ..netdev.dev_manager import NetDeviceManageThread
    from ..logger_manager import Logger

class LoopNetDevice(NetDevice):

    def __init__(self, name: str, logger_manager: 'Logger', netdev_manager: Union['NetDeviceManageThread', None] = None) -> None:
        super().__init__(name, logger_manager)
        self.ipaddr = IPAddress("127.0.0.1")
        self.netdev_manager = netdev_manager
        self.mask = 8

    def send(self, pkb: Packetbuffer) -> int:
        self.debug(pkb)
        self.netstats.tx_packets += 1
        self.netstats.tx_bytes += len(pkb.data)
        # loopback
        self.recv(pkb)
        return len(pkb.data)

    def recv(self, pkb: Packetbuffer) -> Union[Packetbuffer, None]:
        self.debug(pkb, False)
        self.netstats.rx_packets += 1
        self.netstats.rx_bytes += len(pkb.data)
        pkb.indev = self
        if self.netdev_manager != None:
            self.netdev_manager.rcvd_pkb_queue.put(pkb)
    
    def change_ip_address(self, ipaddress: IPAddress, mask: int) -> None:
        return super().change_ip_address(ipaddress, mask)
    
    def change_mac_address(self, mac: MacAddress) -> None:
        return super().change_mac_address(mac)

    def exit(self) -> None:
        pass
