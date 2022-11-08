from typing import TYPE_CHECKING
from src.tcp.tcp_state import TCPStateProcess
from . import TCPHdr
from .sock import TCPSockManager
from ..tcp.segment import TCPSegment
from ..pkb import Packetbuffer
from ..eth import EtherHdr
from ..ip import IPHdr
from ..logger_manager import Logger
from .tcp_out import TCPout
from .tcp_text import TCPText
if TYPE_CHECKING:
    from ..ip.ip import IP

class TCP():
    def __init__(self, ip: 'IP', logger_manager: Logger) -> None:
        self.ip = ip
        self.tcp_sock_manager = TCPSockManager(self)
        self.logger = logger_manager.get_logger("tcp")
        self.tcp_out = TCPout(ip, self.tcp_sock_manager, logger_manager)
        self.tcp_text = TCPText(self.tcp_out, logger_manager)
        self.tcp_state = TCPStateProcess(self.tcp_out, self.tcp_text, self.tcp_sock_manager, logger_manager)

    def tcp_recv(self, pkb: Packetbuffer):
        eth_hdr = EtherHdr.from_bytes(pkb.data)
        if eth_hdr == None:
            return

        ip_hdr = IPHdr.from_bytes(eth_hdr.data)
        if ip_hdr == None:
            return

        tcp_hdr = TCPHdr.from_bytes(ip_hdr.data)
        if tcp_hdr == None:
            return

        tcp_sock = self.tcp_sock_manager.lookup(ip_hdr.dst_ipaddr, ip_hdr.src_ipaddr, tcp_hdr.dst_port, tcp_hdr.src_port)
        self.logger.debug("recv: src:%s:%d, dst:%s:%d seqn %d, ackn %d, win: %d" % (ip_hdr.src_ipaddr, tcp_hdr.src_port, ip_hdr.dst_ipaddr, tcp_hdr.dst_port, tcp_hdr.seqn, tcp_hdr.ackn, tcp_hdr.window))
        self.logger.debug("      %s", tcp_hdr.get_flags())
        if tcp_sock == None:
            self.logger.debug("recv: sock not found")
            return
        
        tcp_segment = TCPSegment(ip_hdr, tcp_hdr)

        self.tcp_state.tcp_process(pkb, tcp_segment, tcp_sock) 

