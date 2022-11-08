from .. import IPAddress
from typing import List, Union
from .. import IPProto, IPHdr
from ...eth import EtherHdr, EtherType
from ...pkb import Packetbuffer
from ...logger_manager import Logger

class FragFlags():
    COMPLETE = 0x0001
    FIRST_IN = 0x0002
    LAST_IN = 0x0004
    FL_IN = FIRST_IN & LAST_IN

class IPFrag(object):

    MAX_FRAG_TTL = 30

    def __init__(self, id: int, src_ipaddr: IPAddress, dst_ipaddr: IPAddress, proto: IPProto, ttl: int, logger_manager: Logger) -> None:
        self.id = id
        self.src_ipaddr = src_ipaddr
        self.dst_ipaddr = dst_ipaddr
        self.proto = proto
        self.ttl = ttl
        self.hlen: int = 0
        self.size: int = 0 # 整个ip报文重组后的的大小，若收到最后一个人报文，则可以计算出整个报文的大小
        self.rszie: int = 0 # 表示收到的报文的大小，每次收到一个报文，则累加该报文的大小
        self.flags: int = 0
        self.pkb_list: List[Packetbuffer] = []
        self.logger_manager = logger_manager
        self.logger = self.logger_manager.get_logger("ip")
    
    def is_complete(self) -> bool:
        return self.flags & FragFlags.COMPLETE == FragFlags.COMPLETE
    
    # 分片报文重组
    def reassemble(self) -> Union[Packetbuffer, None]:
        if not self.is_complete():
            self.logger.debug("Fragment is not complete, drop it")
            return None
        
        total_len = self.hlen + self.size
        if total_len > 65535:
            self.logger.warning("Fragment is too large, drop it")
            return None
        
        frist_pkb = self.pkb_list[0]
        pkb = Packetbuffer(frist_pkb.data)
        for p in self.pkb_list[1:]:
            pkb.data += p.data[(EtherHdr.ETH_HDR_SIZE + self.hlen):]
        pkb.protocol = EtherType.IP
        ip_hdr = IPHdr.from_bytes(pkb.data[EtherHdr.ETH_HDR_SIZE:])
        if ip_hdr == None:
            return None
        ip_hdr.total_len = total_len
        ip_hdr.hdr_len = self.hlen
        ip_hdr.frag_off = 0
        ip_hdr.more_frag = False
        ip_hdr.dont_frag = True
        ip_hdr.frag_off = 0
        ip_hdr.id = 0
        data = ip_hdr.to_bytes()
        pkb.data = pkb.data[:EtherHdr.ETH_HDR_SIZE] + data
        return pkb