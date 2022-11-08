from ..socket import SockAddr
from .segment import TCPSegment
from ..tcp import TCPState
from ..socket.sock import Sock
from ..ip import IPAddress, IPProto
from ..pkb import Packetbuffer
from queue import Queue
from typing import Union, TYPE_CHECKING, List
from .. import HashBucket, Wait
from threading import Lock
if TYPE_CHECKING:
    from ..tcp.tcp import TCP
    from ..stack import TeeceepeeStack

class ByteBuffer(object):
    
    def __init__(self) -> None:
        self.data = b""
        self.lock = Lock()

    def write(self, data: bytes) -> None:
        with self.lock:
            self.data += data      

    def read(self, size: int = 0) -> bytes:
        with self.lock:
            if size != 0:
                data = self.data[:size]
                self.data = self.data[size:]
                return data
            else:
                data = self.data
                self.data = b""
                return data
    def __len__(self) -> int:
        l = 0
        with self.lock:
            l = len(self.data)
        return l

class TCPSockManager(object):
    TCP_EHASH_SIZE = 0x40
    TCP_LHASH_SIZE = 0x20
    TCP_BHASH_SIZE = 0x100
    def __init__(self, tcp: 'TCP') -> None:
        self.listening_socks = HashBucket(self.TCP_EHASH_SIZE)
        self.bind_socks = HashBucket(self.TCP_EHASH_SIZE)
        self.estabilished_socks = HashBucket(self.TCP_EHASH_SIZE)
        self.tcp = tcp
        self.tcp_id: int = 0

    def lookup(self, src_ipaddr: IPAddress, dst_ipaddr: IPAddress, src_port: int, dst_port: int) -> Union['TCPSock', None]:
        sock = self.lookup_estabilished(src_ipaddr, dst_ipaddr, src_port, dst_port)
        if sock == None:
            sock = self.lookup_listen(src_ipaddr, src_port)
        return sock

    def lookup_estabilished(self, src_ipaddr: IPAddress, dst_ipaddr: IPAddress, src_port: int, dst_port: int) -> Union['TCPSock', None]:
        hash = self.estabilished_socks.hash(src_ipaddr, src_port, dst_ipaddr, dst_port)
        for sock in self.estabilished_socks.get(hash):
            assert isinstance(sock, TCPSock)
            assert sock.addr is not None
            if sock.addr.src_ipaddr == src_ipaddr and sock.addr.src_port == src_port and sock.addr.dst_ipaddr == dst_ipaddr and sock.addr.dst_port == dst_port:
                return sock
        return None
    
    def lookup_listen(self, ipaddr: IPAddress, port: int) -> Union['TCPSock', None]:
        hash = self.listening_socks.hash(ipaddr, port)
        for sock in self.listening_socks.get(hash):
            assert isinstance(sock, TCPSock)
            assert sock.addr is not None
            if sock.addr.src_ipaddr == ipaddr and sock.addr.src_port == port:
                return sock
        return None

    def show(self):
        print("ESTABLISHED SOCKETS")
        for bucket in self.estabilished_socks.hash_bucket.values():
            for sock in bucket:
                assert isinstance(sock, TCPSock)
                assert sock.addr is not None
                print(sock.addr.src_ipaddr, sock.addr.src_port, sock.addr.dst_ipaddr, sock.addr.dst_port, sock.state)
        
        print("LISTENING SOCKETS")
        for bucket in self.listening_socks.hash_bucket.values():
            for sock in bucket:
                assert isinstance(sock, TCPSock)
                assert sock.addr is not None
                print(sock.addr.src_ipaddr, sock.addr.src_port, sock.state)

class TCPSockFlag():
    UNSET = 0
    PUSH = 0x01
    ACK_NOW = 0x02
    ACK_LATER = 0x04

class TCPSock(Sock):
    TCP_MAX_BACKLOG = 128
    TCP_DEFAULT_WINDOW_SIZE = 4096
    def __init__(self, stack: 'TeeceepeeStack', proto: IPProto = IPProto.TCP) -> None:
        super().__init__(stack, proto)
        self.backlog = 0
        self.listen_list: List[TCPSock] = [] 
        self.accept_list: List[TCPSock] = []
        self.parent: Union['TCPSock', None] = None
        self.flag = TCPSockFlag.UNSET
        self.state: TCPState = TCPState.CLOSED
        self.bhash_bucket: Union[HashBucket, None] = None
        self.bhash_num = -1

        self.wait_accept = Wait() # 用于等待accept
        self.wait_connect = Wait() # 用于等待连接建立

        self.rcv_buf = ByteBuffer()
        # 保存乱序的tcp segment
        self.rcv_reass: List[TCPSegment] = []

        """
                           snd_una                snd_nxt(TCP_HDR.seq)
                              ↓                       ↓
        ..|12|13|14|15|16|17|18|19|20|21|22|23|24|25|26|27|28|29|30|31|32|33|34|35|36|37|38|39|40|41|..
                            |                       |                                   |
        ------sent, and ack>|<-- sent but not ack ->|<----------- available space ----->| 
                            |                       |                                   |
                            |<--------------------------- snd_wnd --------------------->|

        available = snd_una + snd_wnd - snd_nxt
        
        snd_wnd = 20
        snd_una = 18
        snd_nxt = 26
        available = 18 + 20 - 26 = 12
        """
        self.snd_una = 0 # 指向未确认的第一个字节
        self.snd_nxt = 0 # 可用窗口的第一个字节
        self.snd_wnd = 0 # 发送窗口大小
        self.snd_up = 0
        self.snd_wl1 = 0 # 上一次更新发送窗口的seq
        self.snd_wl2 = 0 # 上一次更新发送窗口的ack
        self.iss = 0 # 初始化的发送序列号
        """
                           rcv_nxt(TCP_HDR.ack)
                              ↓
        ..|12|13|14|15|16|17|18|19|20|21|22|23|24|25|26|27|28|29|30|31|32|33|34|35|36|37|38|39|40|41|..
                            |<----------------------rcvd but not ack------------------->|
        ---rcvd, and ack--->|<------------------------ rcv_wnd ------------------------>|
                            |                                                           |
                            
        """
        self.rcv_nxt = 0 # 等待接收的下一个字节
        self.rcv_wnd = self.TCP_DEFAULT_WINDOW_SIZE # 接收窗口大小
        self.rcv_up = 0
        self.irs = 0 # 初始化的接收序列号

        self.tcp_sock_manager.tcp_id += 1

        self.timeout = 0.0
    
    def recv_notify(self) -> None:
        self.recv_wait.wake_up()

    def send_notify(self) -> None:
        raise NotImplementedError() # Not implemented by tapip

    def send_pkb(self) -> int:
        raise NotImplementedError() # for udp

    def send_buf(self, data: bytes) -> int:
        if self.state in [
            TCPState.CLOSED,
            TCPState.LISTEN,
            TCPState.SYN_SENT,
            TCPState.SYN_RECV
        ]:
            raise Exception("socket is not connected")

        if self.state in [
            TCPState.FIN_WAIT1,
            TCPState.FIN_WAIT2,
            TCPState.LAST_ACK,
            TCPState.CLOSING,
            TCPState.TIME_WAIT
        ]:
            raise Exception("socket is closed")
        
        if self.state in [
            TCPState.ESTABLISHED,
            TCPState.CLOSE_WAIT
        ]:
            pass

        return self.stack.ether.ip.tcp.tcp_text.send_text(self, data)

    def recv(self) -> Packetbuffer:
        raise NotImplementedError() # for udp

    def recv_buf(self, size: int = 0) -> Union[bytes, None]:
        if self.state in [
            TCPState.LISTEN,
            TCPState.SYN_RECV,
            TCPState.SYN_SENT,
            TCPState.LAST_ACK,
            TCPState.CLOSING,
            TCPState.TIME_WAIT,
            TCPState.CLOSED
        ]:
            return
        if self.state == TCPState.CLOSE_WAIT:
            if len(self.rcv_buf) == 0:
                return

        if self.state in [
           TCPState.ESTABLISHED,
           TCPState.FIN_WAIT1,
           TCPState.FIN_WAIT2 
        ]: 
            pass
        
        data = b""
        while len(data) == 0:
            if len(self.rcv_buf) == 0:
                if self.recv_wait.sleep_on() == False:
                    raise Exception("reset by peer")
            data = self.rcv_buf.read(size)
            self.rcv_wnd += len(data)
        
        return data

    def hash(self) -> bool:
        if self.state == TCPState.CLOSED:
            return False
        assert self.addr is not None
        if self.state == TCPState.LISTEN: # 监听状态, 套接字移动到listening hash表中
            self.hash_num = self.tcp_sock_manager.listening_socks.hash(self.addr.src_ipaddr, self.addr.src_port)
            bucket = self.tcp_sock_manager.listening_socks.get(self.hash_num)

        else: # 非监听状态, 套接字移动到established hash表中
            hash_num = self.tcp_sock_manager.estabilished_socks.hash(self.addr.src_ipaddr, self.addr.src_port, self.addr.dst_ipaddr, self.addr.dst_port)
            bucket = self.tcp_sock_manager.estabilished_socks.get(hash_num)
            # check whether the socket is already in estabilished_socks
            for sock in bucket:
                if sock.addr.src_ipaddr == self.addr.src_ipaddr and \
                     sock.addr.src_port == self.addr.src_port and \
                     sock.addr.dst_ipaddr == self.addr.dst_ipaddr and \
                     sock.addr.dst_port == self.addr.dst_port:
                    return False
            self.hash_num = hash_num
        bucket.append(self)
        return True
        
    def unhash(self) -> None:
        if self.hash_bucket == None:
            return
        self.hash_bucket.remove(self.hash_num, self)
        self.hash_bucket = None
        self.hash_num = -1

    def unbhash(self) -> None:
        if self.bhash_bucket == None:
            return
        self.bhash_bucket.remove(self.bhash_num, self)
        self.bhash_bucket = None
        self.hash_num = -1
        
    # tcp和udp的bind是一样的，因此bind函数在inet_socket中实现
    def bind(self) -> int:
        raise NotImplementedError

    def connect(self, sock_addr: SockAddr)  -> None:
        assert self.addr is not None
        self.addr.dst_ipaddr = sock_addr.dst_ipaddr
        self.addr.dst_port = sock_addr.dst_port

        self.state = TCPState.SYN_SENT
        self.iss = self.stack.ether.ip.tcp.tcp_state.tcp_gen_iss()
        # send syn
        self.snd_una = self.iss
        self.snd_nxt = self.iss + 1
        if self.hash() == False:
            self.state = TCPState.CLOSED
            raise Exception("already connected")
        
        assert self.socket is not None
        self.stack.ether.ip.tcp.tcp_out.send_syn(self)
        if not self.wait_connect.sleep_on(): # 等待三次握手成功
            self.unhash()
            self.unbhash()
            self.state = TCPState.CLOSED
            raise Exception("connect reset by peer")

        if self.state != TCPState.ESTABLISHED:
            self.unhash()
            self.unbhash()
            self.state = TCPState.CLOSED
            raise Exception("unexpected error")

    def port_used(self, ipaddr:IPAddress, port: int) -> bool:
        hash = self.tcp_sock_manager.bind_socks.hash(ipaddr, port)
        for sock in self.tcp_sock_manager.bind_socks.get(hash):
            assert isinstance(sock, Sock)
            assert sock.addr is not None
            if sock.addr.src_ipaddr == ipaddr and sock.addr.src_port == port:
                return True
        return False

    def set_port(self, src_ipaddr: IPAddress, src_port: int = 0) -> None:
        assert self.addr is not None
        if src_port == 0:
            src_port = self.get_port(src_ipaddr)
        elif self.port_used(src_ipaddr, src_port):
            raise Exception("Port already used")
        self.addr.src_port = src_port
        self.bhash_num = self.tcp_sock_manager.bind_socks.hash(src_ipaddr, src_port)
        self.tcp_sock_manager.bind_socks.get(self.bhash_num).append(self)
        self.bhash_bucket = self.tcp_sock_manager.bind_socks # 添加bind的socket到bind_socks中

    def get_port(self, ipaddr: IPAddress) -> int:
        for port in range(1024, 65535):
            if not self.port_used(ipaddr, port):
                return port
        raise Exception("No port available")

    def close(self) -> None:
        tcp_out = self.stack.ether.ip.tcp.tcp_out
        if self.state == TCPState.CLOSED: # 已经关闭了的套接字，不用再关闭了
            return

        elif self.state == TCPState.LISTEN: # 表示关闭监听套接字
            self.state = TCPState.CLOSED
            self.unhash() # 从listen hash表中删除
            self.unbhash() # 从bind hash表中删除
            return

        elif self.state == TCPState.SYN_RECV:
            pass

        elif self.state == TCPState.SYN_SENT:
            pass

        elif self.state == TCPState.ESTABLISHED: # 主动关闭
            self.state = TCPState.FIN_WAIT1
            self.stack.ether.ip.tcp.tcp_out.send_fin(self)
            self.snd_nxt += 1

        elif self.state == TCPState.CLOSE_WAIT: # 表示对方已经关闭连接，close是关闭本端
            tcp_out.send_fin(self) # 发送fin
            self.state = TCPState.LAST_ACK # 等待对方的ack
            self.snd_nxt += 1

    def listen(self, backlog: int) -> None:
        if self.addr == None:
            raise Exception("Socket not binded")
        if self.TCP_MAX_BACKLOG < backlog:
            raise ValueError("backlog is too large")
        
        state = self.state

        # 只有状态为CLOSED和LISTEN时才能调用listen
        if state != TCPState.CLOSED and state != TCPState.LISTEN:
            raise Exception("Socket is not in a state to listen")
        
        self.backlog = backlog

        # 切换为监听状态
        self.state = TCPState.LISTEN

        # CLOSED -> LISTEN时，需要将socket加入到监听队列中
        if state == TCPState.CLOSED:
            self.hash()

    def accept(self) -> Union['TCPSock', None]:
        if self.wait_accept.sleep_on() == False:
            return None
        new_tcp_sock = self.accept_list.pop()
        new_tcp_sock.parent = None
        return new_tcp_sock

class TCPSockQueue(Queue): # type: ignore
    def __init__(self, maxsize: int = 0) -> None:
        super().__init__(maxsize)
        self._dead = False

    def destroy(self) -> None:
        self._dead = True
        self.put(None)

    def put(self, sock: Union[TCPSock, None], block: bool = True, timeout: Union[float, None] = None) -> None: # type: ignore
        if self._dead:
            raise Exception("SockQueue is dead")
        super().put(sock, block, timeout) # type: ignore
    
    def get(self, block: bool = True, timeout: Union[float, None]  = None) -> TCPSock:
        sock = super().get(block, timeout) # type: ignore
        if self._dead:
            raise Exception("SockQueue is dead")
        return sock # type: ignore
    
    def get_nowait(self) -> TCPSock: # type: ignore
        sock = super().get_nowait() # type: ignore
        if self._dead:
            raise Exception("SockQueue is dead")
        return sock # type: ignore