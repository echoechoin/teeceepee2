from .tcp_timer import TCPTimer, TCPTimerType
from ..logger_manager import Logger
from .sock import TCPSockManager, TCPSock, TCPSockFlag
from .tcp_out import TCPout
from ..pkb import Packetbuffer
from .segment import TCPSegment
from . import TCPState
from ..socket import SockAddr
from typing import Union
from .tcp_text import TCPText


class TCPStateProcess(object):

    def __init__(self, tcp_out: TCPout, tcp_text: TCPText, sock_manager: TCPSockManager, logger_manager: Logger) -> None:
        self.tcp_out = tcp_out
        self.tcp_text = tcp_text
        self.sock_manager = sock_manager
        self.logger = logger_manager.get_logger("tcp")
        self.tcp_timer = TCPTimer()
        self.tcp_timer.start()

    def tcp_listen(self, sock: TCPSock, pkb: Packetbuffer, segment: TCPSegment) -> None:
        """
        1. 只会处理SYN报文
        2. ignore rst报文
        3. reset ack报文
        """
        tcp_hdr = segment.tcp_hdr
        # 1. 忽略rst报文
        if tcp_hdr.rst:
            return

        # 2. 响应ack报文
        if tcp_hdr.ack:
            return self.tcp_out.send_reset(sock, segment)

        # 3. 处理SYN报文
        if not tcp_hdr.syn:
            return

        new_sock = self.tcp_listen_child_sock(sock, segment)
        new_sock.irs = segment.seqn
        new_sock.iss = self.tcp_gen_iss()
        new_sock.rcv_nxt = segment.seqn + 1 # 为什么要加1：因为这个报文是SYN报文，所以seqn指向的是SYN报文的数据部分，而不是SYN报文的头部
        self.tcp_out.send_synack(new_sock, segment) # 发送tcp被动连接第二次握手
        new_sock.snd_nxt = new_sock.iss + 1 # SYN_ACK报文需要一个seqn，所以snd_nxt要加1
        new_sock.snd_una = new_sock.iss

    def tcp_listen_child_sock(self, sock: TCPSock, segment: TCPSegment) -> TCPSock:
        new_sock = TCPSock(sock.stack, sock.protocol)
        new_sock.state = TCPState.SYN_RECV
        new_sock.addr = SockAddr()
        new_sock.addr.src_ipaddr = segment.ip_hdr.dst_ipaddr
        new_sock.addr.src_port = segment.tcp_hdr.dst_port
        new_sock.addr.dst_ipaddr = segment.ip_hdr.src_ipaddr
        new_sock.addr.dst_port = segment.tcp_hdr.src_port

        # 保存新的sock到established队列
        hash_num = self.sock_manager.estabilished_socks.hash(new_sock.addr.src_ipaddr, new_sock.addr.src_port, new_sock.addr.dst_ipaddr, new_sock.addr.dst_port)
        self.sock_manager.estabilished_socks.get(hash_num).append(new_sock)

        new_sock.parent = sock
        sock.listen_list.append(new_sock)
        return new_sock

    def tcp_synsent(self, sock: TCPSock, segment: TCPSegment):
        # ackn应该在snd_una和snd_nxt之间
        if not (sock.snd_una <= segment.ackn and segment.ackn <= sock.snd_nxt):
            return self.tcp_out.send_reset(sock, segment)
        
        tcp_hdr = segment.tcp_hdr

        # rst报文, 向应用层返回错误
        if tcp_hdr.rst:
            if tcp_hdr.ack: # TODO: RST 和 RST ACK的区别
                sock.state = TCPState.CLOSED # 在connect函数中判断是closed的时候会向应用层返回错误
                sock.wait_connect.wait_exit()
                return

        if tcp_hdr.syn:
            sock.irs = segment.seqn
            sock.rcv_nxt = segment.seqn + 1
            # if send SYN, recv SYN ACK
            if tcp_hdr.ack:
                sock.snd_una = segment.ackn
            
            # 表示收到的是SYN ACK
            # SYN_SENT ------(recv SYN ACK, send ACK)----------> ESTABILISHED
            if sock.snd_una > sock.iss:
                sock.state = TCPState.ESTABLISHED # 在connect函数中：判断是estabilished的时候向应用层返回成功
                sock.snd_wnd = segment.wnd
                sock.snd_wl1 = segment.seqn
                sock.snd_wl2 = segment.ackn
                self.tcp_out.send_ack(sock, segment)
                sock.wait_connect.wake_up()
                self.logger.debug("Active three-way handshake success")
            
            # 表示只收到了SYN
            # SYN_SENT ------(recv SYN, send SYN ACK)----------> SYN_RECV
            # 表示两端同时打开
            # linux 都不支持同时打开
            else:
                sock.state = TCPState.SYN_RECV
                self.tcp_out.send_synack(sock, segment)
        
    def tcp_synrecv_ack(self, sock: TCPSock) -> bool:
        assert sock.parent != None
        if sock.parent.state != TCPState.LISTEN:
            self.logger.debug("tcp synrecv ack parent state error")
            return False

        # 到达了最大连接数
        if sock.parent.backlog <= len(sock.parent.accept_list):
            return False

        # 从listen队列移动到accept队列
        sock.parent.listen_list.remove(sock)
        sock.parent.accept_list.append(sock)
        self.logger.debug("passive three-way handshake success")
        sock.parent.wait_accept.wake_up()
        return True
    
    def tcp_closed(self, sock: Union[TCPSock, None], pkb: Packetbuffer, segment: TCPSegment) -> None:
        self.logger.debug("tcp closed")
        if sock == None:
            self.tcp_out.send_reset(sock, segment)

    def tcp_seq_check(self, sock: TCPSock, segment: TCPSegment) -> bool:
        rcv_end = sock.rcv_nxt + sock.rcv_wnd
        # 保证接收到的数据在接收窗口内
        """
                          rcv_nxt    |seqn-------------------------------last_seqn|  rcv_end
                              ↓      | ↓                                         ↓|    ↓
        ..|12|13|14|15|16|17|18|19|20|21|22|23|24|25|26|27|28|29|30|31|32|33|34|35|36|37|38|39|40|41|..
                            |<----------------------rcvd but not ack------------------->|
        ---rcvd, and ack--->|<------------------------ rcv_wnd ------------------------>|
                            |                                                           |
        """
        if segment.seqn < rcv_end and sock.rcv_nxt <= segment.lastseqn:
            return True
        self.logger.warning("tcp seq check failed: seqn=%d, rcv_end=%d, rcv_nxt=%d, rcv_wnd=%d, lastseqn: %d" % (segment.seqn, rcv_end, sock.rcv_nxt, sock.rcv_wnd, segment.lastseqn))
        return False
    
    # gen init seq number
    def tcp_gen_iss(self) -> int:
        # return random.randint(0, 0xffffffff)
        return 0

    def tcp_update_window(self, sock: TCPSock, segment: TCPSegment) -> None:
        sock.snd_wnd = segment.wnd
        sock.snd_wl1 = segment.seqn
        sock.snd_wl2 = segment.ackn

    # tcp 状态转移
    def tcp_process(self, pkb: Packetbuffer, segment: TCPSegment, sock: TCPSock) -> None:
        tcp_hdr = segment.tcp_hdr

        assert sock.addr != None

        if sock.state == TCPState.CLOSED: # 监听的IP地址和端口已经关闭
            return self.tcp_closed(sock, pkb, segment) # 响应RST报文
            
        if sock.state == TCPState.LISTEN: # 处理tcp被动连接第一次握手
            return self.tcp_listen(sock, pkb, segment)

        if sock.state == TCPState.SYN_SENT: # 处理tcp主动连接第二次握手 | 处理同时连接
            return self.tcp_synsent(sock, segment)

################ 检查序列号 ###############
        if not self.tcp_seq_check(sock, segment):
            # 接收到的数据不在接收窗口内
            self.logger.warning("tcp seq check failed!")
            if tcp_hdr.rst:
                return
            # 表示对端发送的数据不在本端接收窗口内，向对端更新本端的接收窗口
            sock.flag &= TCPSockFlag.ACK_NOW
            
################ 处理RST报文 ###############
        if tcp_hdr.rst:
            if sock.state == TCPState.SYN_RECV:
                if sock.parent != None: # 表示是被动连接
                    sock.parent.listen_list.remove(sock)
                    sock.unhash()
                else:
                    sock.wait_connect.wake_up() # 表示是同时连接
                return

            if sock.state in [
                TCPState.ESTABLISHED, 
                TCPState.FIN_WAIT1,
                TCPState.FIN_WAIT2,
                TCPState.CLOSE_WAIT,
            ]:
                pass
            
            if sock.state in [
                TCPState.CLOSING,
                TCPState.LAST_ACK,
                TCPState.TIME_WAIT,
            ]:
                pass

            sock.state = TCPState.CLOSED
            sock.unbhash()
            sock.unhash()
        
############### 处理ACK报文 ################

        # 只有RST和SYN可以没有ACK
        if not tcp_hdr.ack:
            return
        
        # 处理syn_recv状态
        if sock.state == TCPState.SYN_RECV: # 处理tcp被动连接第三次握手
            # ack 处于发送窗口内, 则1. 切换状态 2. 更新发送窗口
            if sock.snd_una <= segment.ackn and segment.ackn <= sock.snd_nxt:
                if self.tcp_synrecv_ack(sock) == False:
                    self.logger.warning("tcp_synrecv_ack failed!")
                    return

                # 更新未确认序列号
                sock.snd_una = segment.ackn

                # 更新发送窗口
                self.tcp_update_window(sock, segment)

                # 修改状态
                sock.state = TCPState.ESTABLISHED
            else:
                self.tcp_out.send_reset(sock, segment)
                return

        if sock.state in [
            TCPState.ESTABLISHED, # 更新接收窗口
            TCPState.CLOSE_WAIT, # 更新接收窗口
            TCPState.LAST_ACK, # LAST_ACK -> CLOSED
            TCPState.FIN_WAIT1, # FIN_WAIT1 -> FIN_WAIT2
            TCPState.CLOSING # TCP_CLOSING -> TIME_WAIT
        ]:
            """
                              snd_una  ackn           snd_nxt
                                  ↓     ↓                 ↓
            ..|12|13|14|15|16|17|18|19|20|21|22|23|24|25|26|27|28|29|30|31|32|33|34|35|36|37|38|39|40|41|..
                                |                       |                                   |
            ------sent, and ack>|<-- sent but not ack ->|<----------- available space ----->| 
                                |                       |                                   |
                                |<--------------------------- snd_wnd --------------------->|
            """
            # 在ACK发送了但未ACK的内容
            if sock.snd_una < segment.ackn and segment.ackn <= sock.snd_nxt:
                if sock.state == TCPState.FIN_WAIT1:
                    sock.state = TCPState.FIN_WAIT2
                    self.tcp_timer.set_timer(sock, TCPTimerType.FIN_WAIT_2, TCPTimer.TCP_FIN_WAIT2_TIMEOUT)
                    # 处理了ACK报文后，后续继续处理FIN报文： TCP_FIN_WAIT2 -> TCP_TIME_WAIT

                if sock.state == TCPState.CLOSING:
                    sock.state = TCPState.TIME_WAIT
                    self.tcp_timer.set_timer(sock, TCPTimerType.TIME_WAIT, TCPTimer.TCP_TIMEWAIT_TIMEOUT)
                    return

                if sock.state == TCPState.LAST_ACK:
                    sock.state = TCPState.CLOSED
                    sock.unhash()
                    sock.unbhash()
                    return

            # 在ACK没有发送的内容
            elif segment.ackn > sock.snd_nxt:
                self.logger.warning("ackn > snd_nxt %d > %d" % (segment.ackn, sock.snd_nxt))
                return

            # 在ACK已经ACK的内容
            elif segment.ackn < sock.snd_una:
                return
            
            elif segment.ackn == sock.snd_una:
                # 当snd_una == snd_nxt的时候
                pass

            # 更新发送窗口
            self.tcp_update_window(sock, segment)

        elif sock.state == TCPState.FIN_WAIT2:
            return
    
        elif sock.state == TCPState.TIME_WAIT:
            return

################ urgent pointer ################
        # if tcp_hdr.urg:
        #     if sock.state in [
        #         TCPState.ESTABLISHED,
        #         TCPState.FIN_WAIT1,
        #         TCPState.FIN_WAIT2,
        #     ]:
        #         return

        #     if sock.state in [
        #         TCPState.CLOSE_WAIT,
        #         TCPState.CLOSING,
        #         TCPState.LAST_ACK,
        #         TCPState.TIME_WAIT,
        #     ]:
        #         return
            
        #     if sock.state == TCPState.SYN_RECV:
        #         return

################# 处理text ####################
        if sock.state in [
            TCPState.ESTABLISHED,
            TCPState.FIN_WAIT1,
            TCPState.FIN_WAIT2
        ]:
            if tcp_hdr.psh and segment.dlen > 0:
                self.logger.debug("text: recv data")
                self.tcp_text.recv_text(sock, segment, pkb)

################# 处理FIN报文 ##################
        if tcp_hdr.fin:
            # 通知应用层套接字删除了
            # 从established状态转换到close_wait状态
            if sock.state in [
                TCPState.SYN_RECV,
                TCPState.ESTABLISHED,
            ]:
                sock.recv_wait.wait_exit()
                sock.state = TCPState.CLOSE_WAIT # 对端关闭，等待本端应用层关闭
                sock.flag |= TCPSockFlag.PUSH # 表示需要将数据发送给应用层
                sock.recv_notify()
            
            elif sock.state == TCPState.FIN_WAIT1:
                sock.state = TCPState.CLOSING
                return

            elif sock.state in [
                TCPState.CLOSE_WAIT,
                TCPState.CLOSING,
                TCPState.LAST_ACK,
            ]:
                # 表示收到了重复的fin报文，不处理
                return

            elif sock.state == TCPState.TIME_WAIT:
                pass

            elif sock.state == TCPState.FIN_WAIT2:
                sock.state = TCPState.TIME_WAIT
                self.tcp_timer.unset_timer(sock, TCPTimerType.FIN_WAIT_2)
                self.tcp_timer.set_timer(sock, TCPTimerType.TIME_WAIT, TCPTimer.TCP_TIMEWAIT_TIMEOUT)

            sock.rcv_nxt += 1 # 接收到fin报文，接收窗口向后移动一个字节
            sock.flag |= TCPSockFlag.ACK_NOW # 表示需要发送ack报文

        
        if sock.flag & TCPSockFlag.ACK_NOW or sock.flag & TCPSockFlag.ACK_LATER:
            self.tcp_out.send_ack(sock, segment)
