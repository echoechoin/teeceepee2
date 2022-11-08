from ..logger_manager import Logger
from .sock import TCPSock, TCPSockFlag, TCPSockManager
from . import TCPHdr
from .segment import TCPSegment
from typing import Union, TYPE_CHECKING
from ..ip import IPAddress, IPHdr, IPProtoVer, IPTOS, IPProto
from ..eth import EtherHdr, MacAddress, EtherType
from ..pkb import Packetbuffer
if TYPE_CHECKING:
    from ..ip.ip import IP

class TCPout(object):

    def __init__(self, ip: "IP", tcp_sock_manager: TCPSockManager, logger_manager: Logger) -> None:
        self.tcp_sock_manager = tcp_sock_manager
        self.ip = ip
        self.logger_manager = logger_manager
        self.logger = logger_manager.get_logger("tcp") 

    def send_synack(self, sock: TCPSock, segment: TCPSegment) -> None:
        assert sock.addr != None
        out_tcp_hdr = TCPHdr()
        out_tcp_hdr.src_port = sock.addr.src_port
        out_tcp_hdr.dst_port = sock.addr.dst_port
        out_tcp_hdr.data_offset = TCPHdr.TCP_HDR_LEN
        out_tcp_hdr.seqn = sock.iss
        out_tcp_hdr.ackn = sock.rcv_nxt
        out_tcp_hdr.syn = True
        out_tcp_hdr.ack = True
        out_tcp_hdr.window = sock.rcv_wnd
        self.send_out(sock, out_tcp_hdr, segment)

    def send_fin(self, sock: TCPSock):
        assert sock.addr != None
        out_tcp_hdr = TCPHdr()
        out_tcp_hdr.src_port = sock.addr.src_port
        out_tcp_hdr.dst_port = sock.addr.dst_port
        out_tcp_hdr.data_offset = TCPHdr.TCP_HDR_LEN
        out_tcp_hdr.seqn = sock.snd_nxt
        out_tcp_hdr.window = sock.rcv_wnd
        out_tcp_hdr.fin = True
        out_tcp_hdr.ack = True
        out_tcp_hdr.ackn = sock.rcv_nxt
        self.send_out(sock, out_tcp_hdr, None)

    def send_ack(self, sock: TCPSock, segment: Union[TCPSegment, None]) -> None:
        assert sock.addr is not None
        out_tcp_hdr = TCPHdr()
        out_tcp_hdr.src_port = sock.addr.src_port
        out_tcp_hdr.dst_port = sock.addr.dst_port
        out_tcp_hdr.data_offset = TCPHdr.TCP_HDR_LEN
        out_tcp_hdr.seqn = sock.snd_nxt
        out_tcp_hdr.ackn = sock.rcv_nxt
        out_tcp_hdr.ack = True
        out_tcp_hdr.window = sock.rcv_wnd
        sock.flag &= ~TCPSockFlag.ACK_NOW
        sock.flag &= ~TCPSockFlag.ACK_LATER
        self.send_out(sock, out_tcp_hdr, segment)

    def send_reset(self, sock: Union[TCPSock, None], segment: TCPSegment) -> None:
        tcp_hdr = segment.tcp_hdr
        out_tcp_hdr = TCPHdr()
        if tcp_hdr.rst:
            return
        out_tcp_hdr.src_port = tcp_hdr.dst_port
        out_tcp_hdr.dst_port = tcp_hdr.src_port
        if tcp_hdr.ack:
            out_tcp_hdr.seqn = tcp_hdr.ackn
        else:
            out_tcp_hdr.ackn = segment.seqn + segment.len
            out_tcp_hdr.ack = True
        out_tcp_hdr.data_offset = TCPHdr.TCP_HDR_LEN
        out_tcp_hdr.rst = True
        self.send_out(None, out_tcp_hdr, segment)
    
    def send_out(self, sock: Union[TCPSock, None], tcp_hdr: TCPHdr, segment: Union[TCPSegment, None]) -> None:
        src_ipaddr: Union[IPAddress, None] = None
        dst_ipaddr: Union[IPAddress, None] = None
        if segment:
            src_ipaddr = segment.ip_hdr.dst_ipaddr
            dst_ipaddr = segment.ip_hdr.src_ipaddr
        elif sock:
            assert sock.addr != None
            src_ipaddr = sock.addr.src_ipaddr
            dst_ipaddr = sock.addr.dst_ipaddr
        else:
            raise Exception("tcp_send_out: sock and segment is None")
        assert src_ipaddr != None
        assert dst_ipaddr != None
        data = tcp_hdr.to_bytes(src_ipaddr, dst_ipaddr)
        tcp_id = self.tcp_sock_manager.tcp_id
        self.tcp_sock_manager.tcp_id += 1
        ip_hdr = IPHdr(IPHdr.IP_HDR_SIZE, IPProtoVer.IPV4, IPTOS.IPIOS_ROUTINE, IPHdr.IP_HDR_SIZE + len(data), tcp_id, True, False, 0, TCPHdr.TCP_DEFAULT_TTL, IPProto.TCP, 
        src_ipaddr, dst_ipaddr, b'', data, 0)
        eth_hdr = EtherHdr(MacAddress(), MacAddress(), EtherType.IP, ip_hdr.to_bytes())
        pkb = Packetbuffer(eth_hdr.to_bytes())
        if sock and sock.rtdst:
            pkb.rtdst = sock.rtdst
        else:
            if not self.ip.route_cache_manager.route_output(pkb):
                return
            if sock:
                sock.rtdst = pkb.rtdst
        self.logger.debug("send: src:%s:%d, dst:%s:%d seqn %d, ackn %d, win: %d" % (ip_hdr.src_ipaddr, tcp_hdr.src_port, ip_hdr.dst_ipaddr, tcp_hdr.dst_port, tcp_hdr.seqn, tcp_hdr.ackn, tcp_hdr.window))
        self.logger.debug("      %s", tcp_hdr.get_flags())
        self.ip.ip_send_out(pkb)

    def send_syn(self, sock: TCPSock) -> None:
        out_tcp_hdr = TCPHdr()
        assert sock.addr != None
        out_tcp_hdr.src_port = sock.addr.src_port
        out_tcp_hdr.dst_port = sock.addr.dst_port
        out_tcp_hdr.data_offset = TCPHdr.TCP_HDR_LEN
        out_tcp_hdr.syn = True
        out_tcp_hdr.seqn = sock.iss
        out_tcp_hdr.window = sock.rcv_wnd
        self.send_out(sock, out_tcp_hdr, None)
        