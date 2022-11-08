from __future__ import annotations
import os
import fcntl
import socket
import struct
import ctypes
import subprocess


from ..eth import MacAddress
from typing import Union, TYPE_CHECKING
from ..ip import IPAddress, IPNetwork
from .dev import NetDevice
from ..pkb import Packetbuffer
if TYPE_CHECKING:
    from ..logger_manager import Logger

class IOCTL_CMD(object):
    SIOCGIFFLAGS = 0x8913
    SIOCSIFFLAGS = 0x8914
    SIOCSIFADDR = 0x8916
    SIOCSIFNETMASK = 0x891C
    TUNSETIFF = 0x400454CA

class IFF(object):
    IFF_UP = 0x1
    IFF_TAP = 0x0002
    IFF_NO_PI = 0x1000


class TapDevice():
    def __init__(self, name: str, net_device: VethNetDevice) -> None:
        super().__init__()
        self.name: str = name
        self.tap_file_name = "/dev/net/{}".format(self.name)
        self.fd: int = -1
        self.ipaddr: Union[IPAddress, None] = None
        self.mask: int = 32
        self.hwaddr: Union[MacAddress, None] = None
        self.mtu: int = 1500
        self.admin_up: bool = False
        self.netdev = net_device
        self._open()

    def _get_if_flags(self) -> int:
        ifreq = struct.pack("16sh", self.name.encode(), 0)
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            fcntl.ioctl(s, IOCTL_CMD.SIOCGIFFLAGS, ifreq)
        flags = struct.unpack("16sh", ifreq)[1]
        return flags

    def _set_if_flags(self, flags: int) -> None:
        ifreq = struct.pack("16sh", self.name.encode(), flags)
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            fcntl.ioctl(s, IOCTL_CMD.SIOCSIFFLAGS, ifreq)

    def _open(self) -> None:
        if self.fd != -1:
            raise Exception("TapDevice is already opened")
        if os.path.exists(self.tap_file_name) == False:
            subprocess.run("mknod {} c 10 200".format(self.tap_file_name).split())
        self.fd = os.open(self.tap_file_name, os.O_RDWR)
        if self.fd < 0:
            raise Exception("Failed to open %s" % self.tap_file_name)
        ifreq = struct.pack("16sH", self.name.encode(), IFF.IFF_TAP | IFF.IFF_NO_PI)
        fcntl.ioctl(self.fd, IOCTL_CMD.TUNSETIFF, ifreq)

    def close(self) -> None:
        if self.fd != -1:
            os.close(self.fd)
            os.remove(self.tap_file_name)
            self.fd = -1

    def read(self, length: int) -> bytes:
        return os.read(self.fd, length)

    def write(self, data: bytes) -> int:
        l = os.write(self.fileno(), data)
        if l < len(data):
            raise Exception("Failed to write all data")
        return l

    def fileno(self) -> int:
        return self.fd

    def set_ip(self, ip: IPAddress) -> TapDevice:
        ipbytes = socket.inet_aton(str(ip))
        ifreq = struct.pack(
            "16sH2s4s8s",
            self.name.encode(),
            socket.AF_INET,
            b"\x00" * 2,
            ipbytes,
            b"\x00" * 8,
        )
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            fcntl.ioctl(s, IOCTL_CMD.SIOCSIFADDR, ifreq)
        self.ipaddr = ip
        return self

    def set_netmask(self, netmask: int) -> TapDevice:
        netmask = ctypes.c_uint32(~((2 ** (32 - netmask)) - 1)).value
        nmbytes = socket.htonl(netmask)
        ifreq = struct.pack(
            "16sH2sI8s",
            self.name.encode(),
            socket.AF_INET,
            b"\x00" * 2,
            nmbytes,
            b"\x00" * 8,
        )
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            fcntl.ioctl(s, IOCTL_CMD.SIOCSIFNETMASK, ifreq)
        self.mask = netmask
        return self

    def up(self) -> TapDevice:
        flags = self._get_if_flags()
        flags = flags | IFF.IFF_UP
        self._set_if_flags(flags)
        self.admin_up = True
        return self

    def down(self) -> TapDevice:
        flags = self._get_if_flags()
        flags = flags &~ IFF.IFF_UP
        self._set_if_flags(flags)
        self.admin_up = False
        return self

class VethNetDevice(NetDevice):

    def __init__(self, name: str, logger_manager: 'Logger', ipaddress: Union[IPAddress, None], mask: int, tap_ipaddress: Union[IPAddress, None], tap_ip_mask: int = 32) -> None:
        super().__init__(name, logger_manager)
        self.tap = TapDevice("tap-"+name, self)
        if tap_ipaddress != None:
            self.tap.set_ip(tap_ipaddress).set_netmask(tap_ip_mask)
        self.tap.up()
        self.ipaddr, self.mask = ipaddress, mask
        self.stream = self.tap.fileno()

    def change_ip_address(self, ipaddress: Union[IPAddress, None], mask: int) -> None:
        if self.netdev_manager != None:
            # 判断IP地址是否和其他设备冲突
            if ipaddress != None:
                for dev in self.netdev_manager.veth_devices:
                    if dev == self:
                        continue
                    if dev.ipaddr in IPNetwork(str(dev.ipaddr) + "/" + str(dev.mask), strict=False):
                        raise Exception("IP address conflict")

            # 存在路由则重置路由
            if self.ipaddr != None:
                assert self.netdev_manager.route_cache_manager != None
                entry = self.netdev_manager.route_cache_manager.lookup_entry(self.ipaddr)
                if entry != None:
                    self.netdev_manager.route_cache_manager.remove_entry(entry)
                self.netdev_manager.route_cache_manager.add_veth_routes(self)
        self.ipaddr, self.mask = ipaddress, mask
    
    def change_mac_address(self, mac: MacAddress) -> None:
        return super().change_mac_address(mac)

    def send(self, pkb:Packetbuffer) ->int:
        try:
            self.debug(pkb)
            length = self.tap.write(pkb.data)
        except:
            self.netstats.tx_errors += 1
            return -1
        self.netstats.tx_packets += 1
        self.netstats.tx_bytes += length
        return length

    def recv(self, pkb: Union[Packetbuffer, None] = None) -> Union[Packetbuffer, None]:
        try:
            pkb = Packetbuffer()
            data = self.tap.read(self.mtu + 14) # TODO: 14 is ethernet header size
            self.netstats.rx_packets += 1
            self.netstats.rx_bytes += len(data)
        except:
            self.netstats.rx_errors += 1
            return None
        pkb.data = data
        pkb.indev = self
        if self.netdev_manager != None:
            self.netdev_manager.rcvd_pkb_queue.put(pkb)
        # self.debug(pkb, False)
        return pkb

    def exit(self):
        self.tap.close()



def create_tun_device_in_windows(name: str):
    import subprocess
    subprocess.check_call(["netsh", "interface", "ipv4", "set", "subinterface", name, "mtu=1500", "store=persistent"])
    