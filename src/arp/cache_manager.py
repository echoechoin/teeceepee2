from ..logger_manager import Logger
from ..netdev.dev import NetDevice
from ..eth import EtherType, MacAddress, EtherHdr, MacAddressType
from . import ArpHdr, ArpIpHdr, HardwareType, ArpOPCode
from ..pkb import Packetbuffer
from .cache import ArpCache, ArpEntry, ArpEntryState
from ..timer.timer import ReapeatingTimer


class ArpCacheManager():
    def __init__(self, logger_manager: Logger) -> None:
        self.arp_cache = ArpCache(self, logger_manager)
        self.logger = logger_manager.get_logger("arp")
        self.arp_cache_timer = ReapeatingTimer(1, self.arp_cache.arp_timer)

    def arp_request(self, entry: ArpEntry) -> None:
        self.logger.debug("arp request")
        if entry.netdev.ipaddr == None:
            self.logger.warning("arp request: src ipaddr is None")
            return
        
        src_hwaddr = entry.netdev.hwaddr
        src_ipaddr = entry.netdev.ipaddr
        dst_hwaddr = MacAddress("ff:ff:ff:ff:ff:ff")
        dst_ipaddr = entry.ipaddr
        arp_ip_hdr = ArpIpHdr(src_hwaddr, src_ipaddr, dst_hwaddr, dst_ipaddr)
        
        hwtype = HardwareType.ETHERNET
        protype = EtherType.IP
        hwsize = MacAddress.MAC_ADDR_SIZE
        protosize = 4
        opcode = ArpOPCode.ARP_REQUEST
        arp_hdr = ArpHdr(hwtype, protype, hwsize, protosize, opcode, arp_ip_hdr.to_bytes())
        
        dst_hwaddr = MacAddress("ff:ff:ff:ff:ff:ff")
        src_hwaddr = entry.netdev.hwaddr
        eth_type = EtherType.ARP
        ether_hdr = EtherHdr(dst_hwaddr, src_hwaddr, eth_type, arp_hdr.to_bytes())

        entry.netdev.send(Packetbuffer(ether_hdr.to_bytes()))
    
    def arp_reply(self, netdev: NetDevice, pkb: Packetbuffer):
        self.logger.debug("arp reply")
        if netdev.ipaddr == None:
            self.logger.warning("arp reply: src ipaddr is None")
            return

        ether_hdr = EtherHdr.from_bytes(pkb.data)
        if ether_hdr == None:
            return

        arp_hdr = ArpHdr.from_bytes(ether_hdr.data)
        if arp_hdr == None:
            return

        arp_ip_hdr = ArpIpHdr.from_bytes(arp_hdr.data)
        if arp_ip_hdr == None:
            return

        arp_hdr.opcode = ArpOPCode.ARP_REPLY
        arp_ip_hdr.dst_hwaddr = arp_ip_hdr.src_hwaddr
        arp_ip_hdr.dst_ipaddr = arp_ip_hdr.src_ipaddr
        arp_ip_hdr.src_hwaddr = netdev.hwaddr
        arp_ip_hdr.src_ipaddr = netdev.ipaddr

        arp_hdr.data = arp_ip_hdr.to_bytes()
        ether_hdr.data = arp_hdr.to_bytes()
        pkb.data = ether_hdr.to_bytes()
        netdev.send(pkb)
    
    def arp_recv(self, netdev: NetDevice, pkb: Packetbuffer) -> None:
        self.logger.debug("arp recv")
        ether_hdr = EtherHdr.from_bytes(pkb.data)
        if ether_hdr == None:
            self.logger.warning('ArpProcessor: arp_recv: ether_hdr is None')
            return

        arp_hdr = ArpHdr.from_bytes(ether_hdr.data)
        if arp_hdr == None:
            self.logger.warning('ArpProcessor: arp_recv: arp_hdr is None')
            return

        arp_ipv4_hdr = ArpIpHdr.from_bytes(arp_hdr.data)
        if arp_ipv4_hdr == None:
            self.logger.warning('ArpProcessor: arp_recv: arp_ipv4_hdr is None')
            return

        if pkb.mac_type == MacAddressType.OTHERHOST:
            self.logger.warning("arp packet to other host")
            return
        
        if len(pkb.data) < EtherHdr.ETH_HDR_SIZE + ArpHdr.ARP_HDR_SIZE + ArpIpHdr.ARP_IPV4_HDR_SIZE:
            self.logger.warning("arp packet too short")
            return
        
        if ether_hdr.src_hwaddr != arp_ipv4_hdr.src_hwaddr:
            self.logger.warning("arp packet src hwaddr not match")
            return

        if arp_hdr.hwtype != HardwareType.ETHERNET or \
            arp_hdr.protype != EtherType.IP or \
            arp_hdr.hwsize != MacAddress.MAC_ADDR_SIZE or \
            arp_hdr.protosize != 4:
            self.logger.warning("arp packet invalid")
            return
        
        if arp_hdr.opcode not in [ArpOPCode.ARP_REQUEST, ArpOPCode.ARP_REPLY]:
            self.logger.warning("arp packet invalid opcode")
            return

        self._arp_recv(netdev, pkb)
    
    def _arp_recv(self,netdev: NetDevice, pkb: Packetbuffer) -> None:
        ether_hdr = EtherHdr.from_bytes(pkb.data)
        assert ether_hdr != None
        arp_hdr = ArpHdr.from_bytes(ether_hdr.data)
        assert arp_hdr != None
        arp_ipv4_hdr = ArpIpHdr.from_bytes(arp_hdr.data)
        assert arp_ipv4_hdr != None
        
        if arp_ipv4_hdr.dst_hwaddr.is_multicast():
            self.logger.debug("arp packet to multicast")
            return

        if arp_ipv4_hdr.dst_ipaddr != netdev.ipaddr:
            self.logger.debug("arp packet src ipaddr not match")
            return
        
        arp_entry = self.arp_cache.lookup_entry(arp_hdr.protype, arp_ipv4_hdr.src_ipaddr)
        if arp_entry is None and arp_hdr.opcode == ArpOPCode.ARP_REQUEST: # recv arp request, add entry to cache
            self.arp_cache.insert_entry(ArpEntry(
                arp_ipv4_hdr.src_ipaddr,
                arp_ipv4_hdr.src_hwaddr,
                netdev,
                0,
                ArpEntry.MAX_TTL,
                ArpEntryState.RESOLVED,
                arp_hdr.protype
            ))

        if arp_entry is not None:
            arp_entry.hwaddr = arp_ipv4_hdr.src_hwaddr # update hwaddr
            if arp_entry.state == ArpEntryState.WAITING: # if waiting, send pending packet
                try:
                    while True:
                        pkb = arp_entry.pending_packets.get_nowait()
                        ether_hdr = EtherHdr.from_bytes(pkb.data)
                        assert ether_hdr != None
                        ether_hdr.dst_hwaddr = arp_entry.hwaddr
                        ether_hdr.src_hwaddr = netdev.hwaddr
                        pkb.data = ether_hdr.to_bytes()
                        arp_entry.netdev.send(pkb)
                except:
                    pass
            arp_entry.state = ArpEntryState.RESOLVED # change state to resolved
            arp_entry.ttl = ArpEntry.MAX_TTL # reset ttl

        if arp_hdr.opcode == ArpOPCode.ARP_REQUEST:
            self.arp_reply(netdev, pkb)
