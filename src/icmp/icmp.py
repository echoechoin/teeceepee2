from typing import TYPE_CHECKING

from ..logger_manager import Logger
from ..ip import IPHdr

from ..pkb import Packetbuffer
from ..eth import EtherHdr
from .handler import ICMPHandler
from . import ICMPHdr

if TYPE_CHECKING:
    from ..ip.ip import IP

class ICMP(object):

    def __init__(self, ip: 'IP', logger_manager: Logger) -> None:
        self.logger = logger_manager.get_logger("icmp")
        self.ip = ip

    def icmp_recv(self, pkb: Packetbuffer) -> None:
        self.logger.debug("icmp recv")
        ip_hdr = IPHdr.from_bytes(pkb.data[EtherHdr.ETH_HDR_SIZE:])
        if ip_hdr == None:
            return

        if ip_hdr.total_len < ICMPHdr.ICMP_HDR_SZIE:
            self.logger.warning("icmp header is too small")
            return
        
        if IPHdr.checksum(ip_hdr.data) != 0:
            self.logger.warning("icmp checksum error")
            return
        
        icmp_hdr = ICMPHdr.from_bytes(ip_hdr.data)
        if icmp_hdr == None:
            self.logger.warning("icmp header parse error")
            return

        type = icmp_hdr.type
        icmp_handlers = ICMPHandler.get_handler(type)
        if icmp_handlers == None:
            self.logger.warning("icmp type not found")
            return

        icmp_handlers.cb(self.ip, icmp_handlers, pkb, self.logger)