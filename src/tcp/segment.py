
from ..ip import IPHdr
from . import TCPHdr

class TCPSegment(object):
    def __init__(self, ip_hdr: IPHdr, tcp_hdr: TCPHdr) -> None:
        self.seqn = tcp_hdr.seqn 
        self.ackn = tcp_hdr.ackn
        self.dlen = len(tcp_hdr.data) # tcp data length
        self.len = self.dlen + int(tcp_hdr.syn) + int(tcp_hdr.fin) # tcp segment length
        # 通过tcp_hdr计算出的接收到的数据包的最后一个字节的序号。
        self.lastseqn = self.seqn + self.len - 1 if self.len != 0 else self.seqn
        self.wnd = tcp_hdr.window # 对端的接收窗口
        self.up = tcp_hdr.urgptr
        self.prc = 0 # precedence value not used
        self.text = tcp_hdr.data # tcp data
        self.ip_hdr = ip_hdr
        self.tcp_hdr = tcp_hdr
