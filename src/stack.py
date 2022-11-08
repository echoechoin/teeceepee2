from .eth.ether import EthernetThread
from .netdev.dev_manager import NetDeviceManageThread
from .arp.cache_manager import ArpCacheManager
from .netdev.vethdev import VethNetDevice
from .ip import IPAddress
from .ip.route.cache import RouteCacheManager
from .logger_manager import Logger

class TeeceepeeStack():
    
    def __init__(self):
        self.logger_manager = Logger()
        self.arp_cache_manager = ArpCacheManager(self.logger_manager)
        self.netdev_manager = NetDeviceManageThread(self.logger_manager)
        self.route_cache_manager = RouteCacheManager(self.netdev_manager, self.logger_manager)
        self.ether = EthernetThread(self.arp_cache_manager, self.netdev_manager, self.route_cache_manager, self.logger_manager)
        veth0 = VethNetDevice("veth0", self.logger_manager, IPAddress("10.0.0.1"), 24, IPAddress("10.0.0.2"), 24)
        veth1 = VethNetDevice("veth1", self.logger_manager, IPAddress("10.1.1.1"), 24, None)
        self.ether.netdev_manager.add_veth_device(veth0)
        self.ether.netdev_manager.add_veth_device(veth1)
        self.ether.start()


    