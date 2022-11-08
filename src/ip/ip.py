from typing import Union, TYPE_CHECKING
from . import IPAddress
from copy import deepcopy

from ..icmp.icmp import ICMP
from .frag.cache import IPFragCache
from .route import RouteFlags
from .route.cache import RouteCacheManager
from ..eth import MacAddress, MacAddressType, EtherHdr, EtherType
from ..netdev.dev import NetDevice
from ..pkb import Packetbuffer
from ..ip import IPHdr, IPProto
from ..arp.entry import ArpEntry, ArpEntryState
from ..arp.cache_manager import ArpCacheManager
from ..tcp.tcp import TCP
from ..logger_manager import Logger
from logging import DEBUG

if TYPE_CHECKING:
    from ..eth.ether import EthernetThread

class IP(object):

    def __init__(self, ether: 'EthernetThread', arp_cache_manager: ArpCacheManager, route_cache_manager: RouteCacheManager, logger_manager: Logger) -> None:
        self.logger = logger_manager.get_logger("ip")
        self.frag_cache = IPFragCache(logger_manager)
        self.ether = ether
        self.arp_cache_manager = arp_cache_manager
        self.route_cache_manager = route_cache_manager
        self.icmp = ICMP(self, logger_manager)
        self.tcp = TCP(self, logger_manager)
        # self.udp = UDP(self)

    def ip_recv(self, netdev: NetDevice, pkb: Packetbuffer) -> None:
        self.logger.debug("ip recv")
        if pkb.mac_type == MacAddressType.OTHERHOST:
            self.logger.warning("ip_recv: to other host")
            return
        
        if len(pkb.data) < EtherHdr.ETH_HDR_SIZE + IPHdr.IP_HDR_SIZE:
            self.logger.warning("ip_recv: packet too short")
            return

        ether_hdr = EtherHdr.from_bytes(pkb.data)
        if ether_hdr == None:
            self.logger.warning("ip_recv: ether_hdr error")
            return

        ip_hdr = IPHdr.from_bytes(ether_hdr.data)
        if ip_hdr == None:
            self.logger.warning("ip_recv: ip_hdr error")
            return
        
        if ip_hdr.hdr_len < IPHdr.IP_HDR_SIZE:
            self.logger.warning("ip_recv: invalid ip header length")
            return
        
        # ipv4 header checksum check
        if IPHdr.checksum(ether_hdr.data[:ip_hdr.hdr_len]) != 0:
            self.logger.warning("ip_recv: invalid checksum")
            return
        
        if ip_hdr.total_len < ip_hdr.hdr_len or \
            len(pkb.data) < EtherHdr.ETH_HDR_SIZE + ip_hdr.total_len:
            self.logger.warning("ip_recv: invalid total length")
            return
        
        if len(pkb.data) > EtherHdr.ETH_HDR_SIZE + ip_hdr.total_len:
            self.logger.warning("ip_recv: packet too long")
            return

        if self.route_cache_manager.route_input(pkb) == False: # route entry not found
            self.logger.warning("ip_recv: route entry not found")
            return
        
        assert pkb.rtdst != None # assigned by route_input
        if pkb.rtdst.flags == RouteFlags.LOCALHOST:
            self.ip_recv_local(pkb)
        else:
            self.ip_forward(pkb)


    def ip_recv_local(self, pkb: Packetbuffer) -> None:
        assert pkb.rtdst != None
        self.logger.debug("ip_recv_local: {}".format(pkb.rtdst.netdev.name))
        ip_hdr = IPHdr.from_bytes(pkb.data[EtherHdr.ETH_HDR_SIZE:])
        assert ip_hdr != None
        if ip_hdr.frag_off != 0 or ip_hdr.more_frag == True:
            self.logger.debug("recv fragment")
            if ip_hdr.dont_frag == True:
                self.logger.warning("ip_recv_local: fragment packet but dont_frag is set")
                return
        
            new_pkb = self.ip_reassemble(pkb) # 和之前的ip分片报文们一起组装成一个完整的报文
            if new_pkb == None:
                return
            pkb = new_pkb
            
            ip_hdr = IPHdr.from_bytes(pkb.data[EtherHdr.ETH_HDR_SIZE:])
            assert ip_hdr != None
            self.logger.debug("reassemble success")

        # ipv4 header checksum check
        if IPHdr.checksum(pkb.data[EtherHdr.ETH_HDR_SIZE:EtherHdr.ETH_HDR_SIZE + ip_hdr.hdr_len]) != 0:
            self.logger.warning("ip_recv: invalid checksum")
            return

        self.debug_send_recv(pkb)
        if ip_hdr.proto == IPProto.ICMP:
            self.icmp.icmp_recv(pkb)
    
        elif ip_hdr.proto == IPProto.TCP:
            self.tcp.tcp_recv(pkb)

        elif ip_hdr.proto == IPProto.UDP:
            pass
        
        else:
            self.logger.warning("ip_recv_local: unknown protocol or not implemented: {}".format(ip_hdr.proto))
            return


    def ip_forward(self, pkb:Packetbuffer) -> None:
        ip_hdr = IPHdr.from_bytes(pkb.data[EtherHdr.ETH_HDR_SIZE:])
        assert ip_hdr != None
        route_entry = pkb.rtdst
        assert route_entry != None
        netdev = pkb.indev
        dst: Union[IPAddress, None] = None
        if ip_hdr.ttl <= 1: 
            self.logger.warning("ip_forward: ttl <= 1")
            # TODO: send icmp time exceeded
            return

        ip_hdr.ttl -= 1

        if route_entry.flags == RouteFlags.DEFAULT or route_entry.metric > 0:
            dst = route_entry.gateway
        else:
            dst = ip_hdr.dst_ipaddr

        if netdev == route_entry.netdev:
            """
            这里表示从网口收到的报文又从相同的网口发出去，这种情况下，本机会像发送该报文的主机发送ICMP REDIRECT报文
            ** 例子一：

                         SERVER 1.1.1.1
                            |
                        Router1     Router2 
                (192.168.1.2/24)  (192.168.1.1/24)
                            \\       /
                             \\     /
                   PC1-------SWITCH
            (192.168.1.100/24)
            (gw: 192.168.1.1)

            1. PC1设置网关为R2，PC1发送一个报文到SERVER时，会先发送报文到R2。
            2. R2查询路由表，找到R下一跳是R1，又将报文从同一个物理网口发送到R1。
            3. 同时R2也会发送一个ICMP REDIRECT报文到PC1，表示通告对方直接将数据包发向R1，不要发给R2。
            4. PC1收到ICMP REDIRECT报文后，会修改自己的路由表，将自己的路由表中的R2的下一跳改为R1。(我猜的)

            before ICMP REDIRECT PC1-->SWITCH-->R2-->SWITCH-->R1-->SERVER
            after ICMP REDIRECT PC1-->SWITCH-->R1-->SERVER

            ** 例子二：
                        SERVER     Router2 
                (192.168.0.2/16)  (192.168.1.1/16)
                            \\       /
                             \\     /
                   PC1-------SWITCH
            (192.168.1.100/24)
            (gw: 192.168.1.1)
            1. PC1和SERVER通信，PC1认为SERVER不在自己的网络中，通过Router2将数据包发送到SERVER。
            2. R2查询路由表，找到R下一跳是R1，又将报文从同一个物理网口发送到R1。
            3. 同时R2也会发送一个ICMP REDIRECT报文到PC1，表示通告对方直接将数据包发向SERVER，不要发给R2。
            """
            src_route = self.route_cache_manager.lookup_entry(ip_hdr.src_ipaddr)
            if src_route and src_route.metric == 0 and \
                ip_hdr.src_ipaddr in src_route.net and dst in src_route.net:
                self.logger.debug("ip_forward: send icmp redirect")
                # TODO: send icmp redirect
        
        if ip_hdr.hdr_len > route_entry.netdev.mtu: # 如果需要分片
            if ip_hdr.dont_frag == True:
                # 表示需要支持分片才行
                self.logger.debug("ip_forward: send icmp fragmentation needed")
                # TODO: send icmp fragmentation needed
                return
            self.ip_send_fragment(route_entry.netdev, pkb)
        else: # 如果不需要分片 
            self.ip_send_to_dev(route_entry.netdev, pkb)

    def ip_send_out(self, pkb: Packetbuffer) ->None:
        self.logger.debug("ip_send_out")
        ip_hdr = IPHdr.from_bytes(pkb.data[EtherHdr.ETH_HDR_SIZE:])
        assert ip_hdr != None
        if pkb.rtdst == None:
            if not self.route_cache_manager.route_output(pkb):
                self.logger.debug("route not found")
                return
        assert pkb.rtdst != None # assigned by route_output
        if ip_hdr.total_len < pkb.rtdst.netdev.mtu:
            self.ip_send_to_dev(pkb.rtdst.netdev, pkb)
        else:
            self.ip_send_fragment(pkb.rtdst.netdev, pkb)

            
    def ip_send_fragment(self, netdev:NetDevice, pkb:Packetbuffer) -> None:
        self.logger.debug("ip_send_fragment")
        ip_hdr = IPHdr.from_bytes(pkb.data[EtherHdr.ETH_HDR_SIZE:])
        assert ip_hdr != None
        hdr_len = ip_hdr.hdr_len
        data_len = ip_hdr.total_len - hdr_len
        max_len = (netdev.mtu - hdr_len) & ~7
        # 当mtu等于1500时, data_len = 1500 - 20 = 1480 (10111001000), 后三位置为0，就是每个分片的最大长度1480（10111001000）
        frag_offset = 0
        while (data_len > max_len):
            frag_pkb = self.ip_fragment(pkb, ip_hdr, hdr_len, max_len, frag_offset, True)
            self.ip_send_to_dev(netdev, frag_pkb)
            data_len -= max_len
            frag_offset += max_len
        
        # 最后一个分片
        if data_len > 0:
            frag_pkb = self.ip_fragment(pkb, ip_hdr, hdr_len, max_len, frag_offset, False)
            self.ip_send_to_dev(netdev, pkb)
    
    def ip_fragment(self, pkb: Packetbuffer, ip_hdr: IPHdr, hdr_len: int, frag_data_len: int, frag_offset: int, more_frag: bool):
        frag_pkb = Packetbuffer()
        frag_pkb.protocol = pkb.protocol
        frag_pkb.mac_type = pkb.mac_type
        frag_pkb.indev = pkb.indev
        frag_pkb.rtdst = pkb.rtdst

        frag_ip_hdr = deepcopy(ip_hdr)
        data_start = hdr_len + frag_offset
        data_end = hdr_len + frag_offset + frag_data_len
        frag_ip_hdr.data = ip_hdr.data[data_start:data_end]
        frag_ip_hdr.more_frag = more_frag
        frag_ip_hdr.dont_frag = False
        data = frag_ip_hdr.to_bytes()
        eth_hdr_data = EtherHdr(MacAddress(), MacAddress(), EtherType.IP, b"").to_bytes()
        frag_pkb.data = eth_hdr_data + data
        return frag_pkb
    
    def debug_send_recv(self, pkb: Packetbuffer, send: bool = True):
        try:
            if self.logger.level == DEBUG:
                eth_hdr = EtherHdr.from_bytes(pkb.data)
                assert eth_hdr is not None
                ip_hdr = IPHdr.from_bytes(eth_hdr.data)
                assert ip_hdr is not None
                src_ipaddr = ip_hdr.src_ipaddr
                dst_ipaddr = ip_hdr.dst_ipaddr
                if send:
                    self.logger.debug("send: src_ipaddr: %s, dst_ipaddr: %s" %(src_ipaddr, dst_ipaddr))
                else:
                    self.logger.debug("recv: src_ipaddr: %s, dst_ipaddr: %s" %(src_ipaddr, dst_ipaddr))
        except:
            self.logger.warning("debug: %s error" % pkb)

    def ip_send_to_dev(self, netdev: NetDevice, pkb: Packetbuffer) -> None:
        route_enrty = pkb.rtdst
        assert route_enrty != None
        dst: Union[IPAddress, None] = None
        eth_hdr = EtherHdr.from_bytes(pkb.data)
        assert eth_hdr != None
        ip_hdr = IPHdr.from_bytes(eth_hdr.data)
        assert ip_hdr != None

        # 环回
        if route_enrty.flags == RouteFlags.LOCALHOST:
            self.logger.debug("ip_send_to_dev: send to localhost")
           
            eth_hdr.src_hwaddr = eth_hdr.dst_hwaddr = netdev.hwaddr
            pkb.data = eth_hdr.to_bytes()
            self.debug_send_recv(pkb, False)
            netdev.send(pkb)

        # 默认路由
        if route_enrty.flags == RouteFlags.DEFAULT and route_enrty.metric > 0:
            dst = route_enrty.gateway
        else:
            dst = ip_hdr.dst_ipaddr
        assert dst != None
        
        arp_cache_manager = self.arp_cache_manager.arp_cache
        arp_entry = arp_cache_manager.lookup_entry(eth_hdr.eth_type, dst)
        if arp_entry == None:
            arp_entry = ArpEntry(
                ipaddr = dst,
                hwaddr = None,
                netdev = netdev,
                retry_count = ArpEntry.MAX_RETRY_TIMES,
                state = ArpEntryState.WAITING,
                proto = EtherType.IP,
            )
            arp_cache_manager.insert_entry(arp_entry)
            arp_entry.pending_packets.put(pkb)
            self.arp_cache_manager.arp_request(arp_entry)
        elif arp_entry.state == ArpEntryState.WAITING:
            arp_entry.pending_packets.put(pkb)
        else:
            eth_hdr.src_hwaddr = netdev.hwaddr
            assert arp_entry.hwaddr != None
            eth_hdr.dst_hwaddr = arp_entry.hwaddr
            pkb.data = eth_hdr.to_bytes()
            self.debug_send_recv(pkb, False)
            netdev.send(pkb)

    def ip_reassemble(self, pkb:Packetbuffer) -> Union[Packetbuffer,None]:
        ip_hdr = IPHdr.from_bytes(pkb.data[EtherHdr.ETH_HDR_SIZE:])
        assert ip_hdr != None
        frag = self.frag_cache.lookup(ip_hdr.id, ip_hdr.proto, ip_hdr.src_ipaddr, ip_hdr.dst_ipaddr)
        if frag == None:
            frag = self.frag_cache.new_fragment(pkb)
        if self.frag_cache.insert_fragment(pkb, frag) == False:
            self.logger.debug("ip_reassemble: fragment not complete")
            return
        
        if frag.is_complete():
            self.logger.debug("reassemble pbk")
            new_pkb = frag.reassemble()
            assert new_pkb != None
            self.frag_cache.remove_fragment(frag)
            return new_pkb
        else:
            return None
        
        



        

