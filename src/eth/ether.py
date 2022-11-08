from threading import Thread

from ..logger_manager import Logger
from ..ip.route.cache import RouteCacheManager
from ..netdev.dev_manager import NetDeviceManageThread
from . import EtherHdr, MacAddressType, EtherType
from ..pkb import Packetbuffer
from typing import Union
from ..arp.cache_manager import ArpCacheManager
from ..ip.ip import IP

class EthernetThread(Thread):

    def __init__(self,arp_cache_manager: ArpCacheManager, netdev_manager: NetDeviceManageThread, route_cache_manager: RouteCacheManager, logger_manager: Logger) -> None:
        super().__init__()
        self.setDaemon(True)
        self.logger_manager = logger_manager
        self.logger = logger_manager.get_logger("ether")
        self.arp_cache_manager = arp_cache_manager
        self.netdev_manager = netdev_manager
        self.route_cache_manager = route_cache_manager      
        self.ip = IP(self, arp_cache_manager, route_cache_manager, logger_manager)
        self.rcvd_pkb_queue = self.netdev_manager.rcvd_pkb_queue

    def parse_packet(self, pkb: Packetbuffer) -> Union[EtherHdr, None]:
        eth_hdr = EtherHdr.from_bytes(pkb.data)
        if eth_hdr == None:
            return eth_hdr
        mac_addr = eth_hdr.dst_hwaddr
        if mac_addr.is_multicast():
            if mac_addr.is_broadcast():
                pkb.mac_type = MacAddressType.BROADCAST
            else:
                pkb.mac_type = MacAddressType.MULTICAST
        elif pkb.indev != None and mac_addr == pkb.indev.hwaddr:
            pkb.mac_type = MacAddressType.LOCALHOST
        else:
            pkb.mac_type = MacAddressType.OTHERHOST

        pkb.protocol = eth_hdr.eth_type
        return eth_hdr
    
    def run(self) -> None:
        self.netdev_manager.start()
        while True:
            pkb = self.rcvd_pkb_queue.get()
            indev = pkb.indev
            assert indev != None
            eth_hdr = self.parse_packet(pkb)
            if eth_hdr != None:
                if eth_hdr.eth_type == EtherType.IP:
                    self.ip.ip_recv(indev, pkb)

                elif eth_hdr.eth_type == EtherType.ARP:
                    self.arp_cache_manager.arp_recv(indev, pkb)

                else:
                    # self.logger.warning("EthernetThread: unknown ether type: %s" % eth_hdr.eth_type)
                    continue
                    
