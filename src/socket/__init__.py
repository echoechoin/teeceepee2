from abc import ABC
from enum import Enum
from ..ip import IPAddress
from .. import Wait
from ..ip import IPProto
from abc import ABC, abstractmethod
from typing import Tuple, Union, TYPE_CHECKING

if TYPE_CHECKING:
    from .sock import Sock
    from ..stack import TeeceepeeStack

class SocketFamily(Enum):
    AF_INET = 1

class SocketType(Enum):
    pass

class SocketState(Enum):
    UNCONNECTED = 1
    BIND = 2
    LISTEN = 3
    CONNECTING = 4
    CONNECTED = 5

class Socket(ABC):
    def __init__(self, stack: 'TeeceepeeStack', state: SocketState, family: SocketFamily, type: SocketType) -> None:
        # stack info
        self.stack = stack
        self.netdev_manager = stack.netdev_manager
        self.ether = stack.ether
        self.ip = stack.ether.ip
        self.tcp = stack.ether.ip.tcp
        self.tcp_sock_manager = stack.ether.ip.tcp.tcp_sock_manager
        self.loggers = stack.ether.logger_manager.get_logger("tcp")

        self.state = state
        self.family = family
        self.type = type
        self.sleep = Wait()
        self.sock: Union['Sock', None] = None
    
    @abstractmethod
    def socket(self, protocol: IPProto):
        "socket"

    @abstractmethod
    def bind(self, address: Tuple[str, int]) -> None:
        "bind"

    @abstractmethod
    def listen(self, backlog: int) -> None:
        "listen"

    @abstractmethod
    def accept(self, new_socket: 'Socket') -> None:
        "accept"
        
    @abstractmethod
    def connect(self, sock_addr: 'SockAddr'):
        "connect"
    
    @abstractmethod
    def close(self):
        "close"

    @abstractmethod
    def read(self, size: int = 0) -> bytes:
        "read"

    @abstractmethod
    def write(self, data: bytes) -> None:
        "write"

    @abstractmethod
    def send(self):
        "send"

    @abstractmethod
    def recv(self):
        "recv"


class SockAddr(object):
    def __init__(self) -> None:
        self.src_ipaddr: Union[IPAddress, None] = None
        self.src_port: int = 0
        self.dst_ipaddr: Union[IPAddress, None] = None
        self.dst_port: int = 0