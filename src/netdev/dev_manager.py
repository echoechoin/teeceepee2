from threading import Thread
from typing import List, Union
from select import select
from ..logger_manager import Logger
from ..ip.route.cache import RouteCacheManager
from ..pkb import PKBQueue
from .loopdev import LoopNetDevice
from .vethdev import TapDevice, VethNetDevice
from ..ip import IPAddress, IPNetwork


class NetDeviceManageThread(Thread):
    MAX_RECV_PKB_CACHE_SIZE = 8192
    def __init__(self, logger_manager: Logger) -> None:
        super().__init__()
        self.logger = logger_manager.get_logger("netdev")
        self.setDaemon(True)
        self.loop_device = LoopNetDevice("lo",logger_manager, self)
        self.veth_devices: List[VethNetDevice] = []
        self.rcvd_pkb_queue = PKBQueue(self.MAX_RECV_PKB_CACHE_SIZE) # all pkb which is received by netdev
        self.route_cache_manager: Union[RouteCacheManager, None] = None
    
    def add_veth_device(self, dev: VethNetDevice) -> None:
        if self.route_cache_manager == None:
            raise Exception("route cache manager is not set")

        # 判断是否存在同名的设备
        for veth in self.veth_devices:
            if veth.name == dev.name:
                raise Exception("veth device %s already exists" % dev.name)

        # 判断是否有同网段的设备
        for veth in self.veth_devices:
            if veth.ipaddr != None:
                if dev.ipaddr in IPNetwork(str(veth.ipaddr) + "/" + str(veth.mask), strict=False):
                    raise Exception("ipaddr conflict")

        # 判断是否有同MAC地址的设备
        for veth in self.veth_devices:
            if veth.hwaddr == dev.hwaddr:
                raise Exception("hwaddr conflict")
        
        # 添加设备
        self.veth_devices.append(dev)
        dev.netdev_manager = self

        # 如果设备有IP地址，则添加到本地路由和同网段路由
        self.route_cache_manager.add_veth_routes(dev)

    def local_ip_addr(self, ipaddr: IPAddress) -> bool:
        # all ip address
        if ipaddr == IPAddress("0.0.0.0"):
            return True
        
        # loopback ip address
        if IPNetwork(str(ipaddr) + "/" + str(self.loop_device.mask)) == IPNetwork(str(self.loop_device.ipaddr) + "/" + str(self.loop_device.mask)):
            return True
        
        # veth ip address
        for dev in self.veth_devices:
            if dev.ipaddr == ipaddr:
                return True
        
        return False

    def run(self) -> None:
        while True:
            rlist: List[TapDevice] = [dev.tap for dev in self.veth_devices]
            rlist, _, _ = select(rlist, [], [])
            for tap in rlist:
                tap.netdev.recv()
