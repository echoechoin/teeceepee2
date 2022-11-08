from ...logger_manager import Logger
from . import IPFrag, IPHdr
from typing import List, Union
from threading import Lock
from ..ip import IPAddress
from . import FragFlags
from .. import IPProto
from ...eth import EtherHdr
from ...pkb import Packetbuffer
from ...timer.timer import ReapeatingTimer

class IPFragCache(object):

    def __init__(self, logger_manager: Logger) -> None:
        self.logger = logger_manager.get_logger("ip")
        self.ipv4_frag_list: List[IPFrag] = []
        self.ipv4_frag_list_lock: Lock = Lock()
        self.frag_timer = ReapeatingTimer(1, self.timer)
        self.frag_timer.start()

    def lookup(self, id: int, proto: IPProto, src_ipaddr: IPAddress, dst_ipaddr: IPAddress) -> Union[IPFrag, None]:
        with self.ipv4_frag_list_lock:
            for frag in self.ipv4_frag_list:
                if frag.id == id and frag.proto == proto and frag.src_ipaddr == src_ipaddr and frag.dst_ipaddr == dst_ipaddr:
                    return frag
            return None

    def new_fragment(self, pkb: Packetbuffer) -> IPFrag:
        with self.ipv4_frag_list_lock:
            ip_hdr = IPHdr.from_bytes(pkb.data[EtherHdr.ETH_HDR_SIZE:])
            assert ip_hdr != None
            frag_id = ip_hdr.id
            frag_src = ip_hdr.src_ipaddr
            frag_dst = ip_hdr.dst_ipaddr
            frag_pro = ip_hdr.proto
            ttl = IPFrag.MAX_FRAG_TTL

            frag = IPFrag(frag_id, frag_src, frag_dst, frag_pro, ttl, self.logger_manager)
            self.ipv4_frag_list.append(frag)
            return frag

    # 收集分片报文
    def insert_fragment(self, pkb: Packetbuffer, frag: IPFrag) -> bool:
        with self.ipv4_frag_list_lock:
            if frag.is_complete():
                self.logger.debug("Fragment is complete, this is retransmission packet, drop it")
                return False

            ip_hdr = IPHdr.from_bytes(pkb.data[EtherHdr.ETH_HDR_SIZE:])
            assert ip_hdr != None

            index = -1
            if ip_hdr.more_frag == False: # 表示最后一个分片
                if frag.flags & FragFlags.LAST_IN: # 表示重传了最后一个分片
                    self.logger.debug("Fragment is duplicate, this is retransmission packet, drop it") # 
                    return False
                frag.flags |= FragFlags.LAST_IN
                frag.size = ip_hdr.frag_off + ip_hdr.total_len - ip_hdr.hdr_len
                index = len(frag.pkb_list)
                
            else:
                index = len(frag.pkb_list)# 从最大开始找该报文的插入位置，如果该报文最大，就插入到最后一个位置
                next_pkb_ip_hdr :Union[IPHdr, None] = None
                for tmp_pkb in reversed(frag.pkb_list):
                    tmp_pkb_ip_hdr = IPHdr.from_bytes(tmp_pkb.data[EtherHdr.ETH_HDR_SIZE:])
                    assert tmp_pkb_ip_hdr != None
                    if tmp_pkb_ip_hdr.frag_off == ip_hdr.frag_off:
                        self.logger.debug("Fragment is duplicate, this is retransmission packet, drop it")
                        return False
                    """
                        <----------------------------|
                    [0]  [X]  [200]  [300]  [400]  [500]
                    find X = 100 < 200, insert [100] before [200]
                    """
                    if tmp_pkb_ip_hdr.frag_off < ip_hdr.frag_off:
                        index = frag.pkb_list.index(tmp_pkb) + 1
                        next_pkb_ip_hdr = tmp_pkb_ip_hdr
                        break
                # 要求每个报文的报文头部都是相同长度的
                if frag.hlen != 0 and frag.hlen != ip_hdr.hdr_len:
                    self.logger.warning("Fragment header length is not equal, drop it")
                    return False
                else:
                    frag.hlen = ip_hdr.hdr_len
                
                # 要求上一个分片报文的偏移 + 上一个报文的data长度 <= 收到的报文的偏移: 
                # 100 + len([100].data) <= 200. 小于表示中间还有分片没有收到，等于表示[100]和[200]之间没有分片了
                if next_pkb_ip_hdr and next_pkb_ip_hdr.frag_off + next_pkb_ip_hdr.total_len - next_pkb_ip_hdr.hdr_len > ip_hdr.frag_off:
                    self.logger.warning("Fragment is overlap, drop it")
                    return False

                # 第一个分片报文
                if ip_hdr.frag_off == 0:
                    frag.flags |= FragFlags.FIRST_IN

            frag.pkb_list.insert(index, pkb)   
            frag.rszie += ip_hdr.total_len - ip_hdr.hdr_len
            self.logger.debug("flag: first in: %s, last in: %s, frag_size:%d, frag_rsize:%d", 
                        "true" if frag.flags & FragFlags.FIRST_IN else "false",
                        "true" if frag.flags & FragFlags.LAST_IN else "false",
                        frag.size, frag.rszie)
            # 表示分片收齐了
            if frag.flags & FragFlags.FIRST_IN and frag.flags & FragFlags.LAST_IN and frag.rszie == frag.size:
                frag.flags |= FragFlags.COMPLETE
                return True
            
            return False

    def remove_fragment(self, frag: IPFrag):
        with self.ipv4_frag_list_lock:
            self.ipv4_frag_list.remove(frag)

    def timer(self, delta: int = 1):
        with self.ipv4_frag_list_lock:
            for frag in self.ipv4_frag_list:
                if frag.flags & FragFlags.COMPLETE:
                    continue
                frag.ttl -= delta
                if frag.ttl <= 0:
                    self.ipv4_frag_list.remove(frag)
                    # TODO: icmp time exceeded
                    self.logger.debug("Fragment timeout, drop it")