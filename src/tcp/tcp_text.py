from .tcp_out import TCPout
from .tcp_timer import TCPTimer, TCPTimerType
from ..ip import  IPHdr
from . import TCPHdr
from ..logger_manager import Logger
from ..pkb import Packetbuffer
from .segment import TCPSegment
from .sock import TCPSockFlag
from .sock import TCPSock

class TCPText(object):

    def __init__(self, tcp_out: TCPout, logger_manager: Logger) -> None:
        self.logger = logger_manager.get_logger("tcp")
        self.tcp_out = tcp_out

    def adjacent_segment_head(self, rcv_nxt: int, segment: TCPSegment) -> None:
        """
        处理这种情况
                    |<-------------------dlen---------------->|
                    |seq    rcv_nxt                           |
                    | ↓        ↓                              |
         ..|12|13|14|15|16|17|18|19|20|21|22|23|24|25|26|27|28|29|30|31|32|33|34|35|36|37|38|39|40|41|..
                             |<----------------------rcvd but not ack------------------->|
         ---rcvd, and ack--->|<------------------------ rcv_wnd ------------------------>|
                             |                                                           |
        转换为
                             |<--------------dlen------------>|
                             |rcv_nxt(seq)                    |
                             | ↓                              |
         ..|12|13|14|15|16|17|18|19|20|21|22|23|24|25|26|27|28|29|30|31|32|33|34|35|36|37|38|39|40|41|..
                             |<----------------------rcvd but not ack------------------->|
         ---rcvd, and ack--->|<------------------------ rcv_wnd ------------------------>|
                             |                                                           |

        """
        if segment.seqn > rcv_nxt:
            return
        if rcv_nxt - segment.seqn >= segment.dlen:
            return
        segment.dlen = segment.dlen - (rcv_nxt - segment.seqn)
        segment.text = segment.text[rcv_nxt - segment.seqn:]
        segment.seqn = rcv_nxt

    def write_buf(self, sock: 'TCPSock', data: bytes) -> None:
        sock.rcv_buf.write(data)
        l = len(data)
        sock.rcv_wnd -= l
        sock.rcv_nxt += l

    def reass_text(self, sock: 'TCPSock', segment: TCPSegment, pkb:Packetbuffer) -> None:
        
        insert_pos = index = len(sock.rcv_reass)
        """
                          |<-------------------dlen---------------->|
                          |seq                                      |
                          | ↓                                       |
         ..|12|13|14|15|16|17|18|19|20|21|22|23|24|25|26|27|28|29|30|31|32|33|34|35|36|..
            | ↑                 |                             | ↑                     |
            | prv_seq           |                             | nxt_seq               |
            |<--------- dlen--->|                             |<--------- dlen------->|
        
        转换为：
                                |<-------------dlen---------------->|
                                |seq                                |
                                | ↓                                 |
         ..|12|13|14|15|16|17|18|19|20|21|22|23|24|25|26|27|28|29|30|31|32|33|34|35|36|..
            | ↑                 |                             | ↑                     |
            | prv_seq           |                             | nxt_seq               |
            |<--------- dlen--->|                             |<--------- dlen------->|
        再转换为：
                                |<----------dlen------------->|
                                |seq                          |
                                | ↓                           |
         ..|12|13|14|15|16|17|18|19|20|21|22|23|24|25|26|27|28|29|30|31|32|33|34|35|36|..
            | ↑                 |                             | ↑                     |
            | prv_seq           |                             | nxt_seq               |
            |<--------- dlen--->|                             |<--------- dlen------->|
        """
        for i in range(index):
            if sock.rcv_reass[i].seqn > segment.seqn:
                insert_pos = i
                if i != 0:
                    prev_seg = sock.rcv_reass[i-1]
                    self.adjacent_segment_head(prev_seg.seqn + prev_seg.dlen, prev_seg)        
        for i in range(index):
            if sock.rcv_reass[i].seqn + sock.rcv_reass[i].dlen > segment.seqn + segment.dlen:
                if sock.rcv_reass[i].seqn < sock.rcv_reass[i].seqn + sock.rcv_reass[i].dlen:
                    segment.dlen = sock.rcv_reass[i].seqn - segment.seqn
                    break
        sock.rcv_reass.insert(insert_pos, segment)
        # 合并相邻的segment并且写入rcv_buf
        while True:
            seg = sock.rcv_reass[0]
            if seg.seqn != sock.rcv_nxt:
                break
            self.write_buf(sock, seg.text)
            sock.rcv_reass.remove(seg)
            if len(sock.rcv_reass) == 0:
                break

    def recv_text(self, sock: 'TCPSock', segment: TCPSegment, pkb:Packetbuffer):
        if sock.rcv_wnd == 0:
            self.logger.debug("recv_text: rcv_wnd == 0")
            return
        
        self.adjacent_segment_head(sock.rcv_nxt, segment)
        # 表示没有待重组报文，且本次收到的报文就是第一个报文。直接写到读buffer中
        if sock.rcv_nxt == segment.seqn and len(sock.rcv_reass) == 0:
            self.logger.debug("recv_text: dirrectly")
            self.write_buf(sock, segment.text)
            if segment.tcp_hdr.psh:
                sock.flag |= TCPSockFlag.PUSH
                sock.flag |= TCPSockFlag.ACK_LATER
        # 否则走重组过程的函数
        else:
            self.logger.debug("recv_text: reassemble")
            self.reass_text(sock, segment, pkb)
        if sock.flag & TCPSockFlag.PUSH:
            sock.recv_notify()

    def init_text(self, sock: 'TCPSock', data: bytes) -> TCPHdr:
        assert sock.addr is not None
        tcp_hdr = TCPHdr()
        tcp_hdr.src_port = sock.addr.src_port
        tcp_hdr.dst_port = sock.addr.dst_port
        tcp_hdr.seqn = sock.snd_nxt
        tcp_hdr.ackn = sock.rcv_nxt
        sock.snd_nxt += len(data)
        sock.snd_wnd -= len(data)
        tcp_hdr.data_offset = TCPHdr.TCP_HDR_LEN
        tcp_hdr.ack = True
        tcp_hdr.psh = True
        tcp_hdr.window = sock.rcv_wnd
        tcp_hdr.data = data
        return tcp_hdr

    def send_text(self, sock: 'TCPSock', data: bytes) -> int:
        assert sock.rtdst is not None
        sgement_max_size = sock.rtdst.netdev.mtu - IPHdr.IP_HDR_SIZE - TCPHdr.TCP_HDR_LEN
        data_len = len(data[0:sock.snd_wnd])
        snd_len = 0
        while (snd_len < data_len):
            send_len_once = min(data_len, sgement_max_size)
            snd_len += send_len_once
            sock.tcp_sock_manager.tcp_id += 1
            tcp_hdr = self.init_text(sock, data[0:send_len_once])
            self.tcp_out.send_out(sock, tcp_hdr, None)
            data = data[send_len_once:]
        # update snd_wnd
        if data_len < len(data):
            sock.stack.ether.ip.tcp.tcp_state.tcp_timer.set_timer(sock, TCPTimerType.PERSIST,TCPTimer.TCP_PERSIST_TIMEOUT)
        return snd_len
