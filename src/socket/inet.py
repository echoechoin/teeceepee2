from ..ip import IPProto
from ..tcp.sock import TCPSock
from . import Socket, SockAddr
from . import SocketFamily, SocketState, SocketType
from typing import Any, Callable, Dict, Tuple, Type, Union, TYPE_CHECKING
from ..ip import IPAddress
if TYPE_CHECKING:
    from ..stack import TeeceepeeStack
    from .sock import Sock


class InetSocketType(SocketType):
    SOCK_STREAM = 1
    SOCK_DGRAM = 2
    SOCK_RAW = 3


class InetSocketTypeTableEntry(object):
    def __init__(self, type: InetSocketType, protocol: IPProto, sock: Union[Type['Sock'], Callable[..., 'Sock']]) -> None:
        self.type = type
        self.protocol = protocol
        self.sock = sock


class InetSocketTypeTable(object):
    inet_type_table: Dict[InetSocketType, InetSocketTypeTableEntry] = {}

    @classmethod
    def resigter_inet_socket_type(cls, type: InetSocketType, protocol: IPProto) -> Callable[..., Any]:
        def wrapper(sock_class: Union[Type['Sock'], Callable[..., 'Sock']]) -> None:
            cls.inet_type_table[type] = InetSocketTypeTableEntry(type, protocol, sock_class)
        return wrapper
    
    @classmethod
    def get(cls, type: InetSocketType) -> Union[InetSocketTypeTableEntry, None]:
        return cls.inet_type_table.get(type, None)

@InetSocketTypeTable.resigter_inet_socket_type(InetSocketType.SOCK_STREAM, IPProto.TCP)
def tcp_socket(stack: 'TeeceepeeStack', proto: IPProto) -> TCPSock:
    return TCPSock(stack)


class InetSocket(Socket):

    def __init__(self, stack: 'TeeceepeeStack', state: SocketState, family: SocketFamily, type: InetSocketType) -> None:
        super().__init__(stack, state, family, type)
    
    def socket(self, protocol: IPProto):
        inet_socket_type_entry = InetSocketTypeTable.get(InetSocketType.SOCK_STREAM)
        if inet_socket_type_entry == None:
            raise ValueError("sock type not found in inet socket type table")
        self.sock = inet_socket_type_entry.sock(self.stack, protocol)
            
        if protocol == IPProto.UNKNOWN:
            protocol = inet_socket_type_entry.protocol
        self.sock.protocol = protocol
        self.sock.socket = self

    def bind(self, address: Tuple[str, int]) -> None:
        try:
            src_ipaddr, src_port = address[0:2]
            src_ipaddr = IPAddress(src_ipaddr)
        except:
            raise ValueError("address is invalid")

        assert isinstance(src_port, int)
        if src_port < 0 or src_port > 65535:
            raise ValueError("port out of range")

        # 判断是否为本地的地址
        if not self.netdev_manager.local_ip_addr(src_ipaddr):
            raise ValueError("address is not local")

        assert self.sock != None
        self.sock.addr = SockAddr()
        self.sock.addr.src_ipaddr = src_ipaddr
        # 判断端口是否被占用
        self.sock.set_port(src_ipaddr, src_port)


    def listen(self, backlog: int) -> None:
        if not isinstance(self.sock, TCPSock):
            raise ValueError("socket is not tcp socket")
        self.sock.listen(backlog)

    def accept(self, new_socket: Socket) -> None:
        assert self.sock != None
        new_sock = self.sock.accept()
        new_socket.sock = new_sock

    def connect(self, sock_addr: SockAddr) -> None:
        assert self.sock != None
        if self.sock.addr == None:
            raise ValueError("socket is not bind")
        
        if self.sock.addr.dst_port != 0:
            raise Exception("can not connect twice")

        self.sock.connect(sock_addr)

    def close(self):
        assert self.sock != None
        self.sock.close()
        self.sleep.wait_exit() # 将其他阻塞接口唤醒，返回错误
        self.sock = None

    def read(self, size: int = 0) -> bytes:
        assert self.sock != None
        ret = self.sock.recv_buf(size)
        if ret == None:
            raise Exception("socket is not connect")
        return ret

    def write(self, data: bytes) -> None:
        assert self.sock != None
        self.sock.send_buf(data)

    def send(self):
        "send"

    def recv(self):
        "recv"


