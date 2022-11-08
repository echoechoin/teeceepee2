from typing import Union, List, TYPE_CHECKING
from threading import Lock
from . import RouteEntry, RouteFlags
from .. import IPAddress, IPNetwork
from .. import IPHdr
from ...pkb import Packetbuffer
from ...logger_manager import Logger
from ...eth import EtherHdr
if TYPE_CHECKING:
    from ...netdev.dev_manager import NetDeviceManageThread
    from ...netdev.dev import NetDevice

class RouteCacheManager(object):

    def __init__(self, netdev_manager: 'NetDeviceManageThread', logger_manager: Logger) -> None:
        self.entries: List[RouteEntry] = []
        self.entries_lock = Lock()
        self.loop_device = netdev_manager.loop_device
        self.veth_devices = netdev_manager.veth_devices
        netdev_manager.route_cache_manager = self
        self.logger_manager = logger_manager
        self.logger = self.logger_manager.get_logger("ip")

        self.route_init()
    
    def add_entry(self, entry:RouteEntry) -> None:
        with self.entries_lock:
            self.entries.append(entry)

    def remove_entry(self, entry: RouteEntry) -> None:
        with self.entries_lock:
            self.entries.remove(entry)

    def lookup_entry(self, addr: Union[IPAddress, IPNetwork]) -> Union[RouteEntry, None]:
        with self.entries_lock:
            for entry in self.entries:
                if addr in entry.net:
                    return entry
            return None

    def show(self) -> None:
        with self.entries_lock:
            print("%-20s%-20s%-20s%-10s%-10s" % ("Destination", "Gateway", "Genmask", "Metric", "Iface"))
            for entry in self.entries:
                if entry.flags == RouteFlags.LOCALHOST:
                    continue
                if entry.flags == RouteFlags.DEFAULT:
                    print("%-20s" % "default", end="")
                else:
                    print("%-20s" % entry.net, end="")
                if entry.gateway is not None:
                    print("%-20s" % entry.gateway, end="")
                else:
                    print("%-20s" % "*", end="")
                
                print("%-20s" % entry.net.netmask, end="")
                print("%-10s" % entry.metric, end="")
                print("%-10s" % entry.netdev.name)

    def route_input(self, pkb: Packetbuffer) -> bool:
        ip_hdr = IPHdr.from_bytes(pkb.data[EtherHdr.ETH_HDR_SIZE:])
        assert ip_hdr != None
        route_entry = self.lookup_entry(ip_hdr.dst_ipaddr)
        if route_entry is None:
            # TODO: RFC 1812: send ICMP unreachable
            return False
        pkb.rtdst = route_entry
        return True
    
    def route_output(self, pkb: Packetbuffer) -> bool:
        ip_hdr = IPHdr.from_bytes(pkb.data[EtherHdr.ETH_HDR_SIZE:])
        assert ip_hdr != None
        route_entry = self.lookup_entry(ip_hdr.dst_ipaddr)
        if route_entry == None:
            self.logger.debug("No route entry to {}".format(str(ip_hdr.dst_ipaddr)))
            return False
        pkb.rtdst = route_entry
        netdev_addr =  route_entry.netdev.ipaddr
        assert netdev_addr != None
        ip_hdr.src_ipaddr = netdev_addr
        pkb.data = pkb.data[:EtherHdr.ETH_HDR_SIZE] + ip_hdr.to_bytes()
        return True

    def route_add(self, route_entry: RouteEntry) -> None:
        with self.entries_lock:
            self.entries.append(route_entry)
    
    def route_init(self):
        loop_netdev = self.loop_device
        route_entry = RouteEntry(
            IPNetwork(str(loop_netdev.ipaddr) + "/" + str(loop_netdev.mask), strict=False),
            None,
            RouteFlags.LOCALHOST,
            0,
            loop_netdev
        )
        self.route_add(route_entry)
    
    def add_veth_routes(self, dev: 'NetDevice') -> None:
        if dev.ipaddr != None:
            # 路由到本地
            route_entry = RouteEntry(
                IPNetwork(str(dev.ipaddr) + "/" + "32", strict=False),
                None,
                RouteFlags.LOCALHOST,
                0,
                self.loop_device
            )
            self.route_add(route_entry)

            # 路由到同网段
            route_entry = RouteEntry(
                IPNetwork(str(dev.ipaddr) + "/" + str(dev.mask), strict=False),
                None,
                RouteFlags.NONE,
                0,
                dev
            )
            self.route_add(route_entry)
