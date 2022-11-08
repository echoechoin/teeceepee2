from typing import Union, Tuple
from . import SockAddr, Socket
from . import SocketFamily, SocketState
from ..ip import IPAddress, IPProto
from .inet import InetSocketType
from .inet import InetSocket
from ..stack import TeeceepeeStack
from . import Socket


AF_INET = 1

SOCK_STREAM = 1
SOCK_DGRAM = 2
SOCK_RAW = 3

class socket(object):
    def __init__(self, stack: TeeceepeeStack, family: int, type: int, protocol: int = 0):
        self.stack = stack
        self.family = family
        self.type = type
        self.protocol = protocol
        self.socket = self._allocate_socket()
    
    def _allocate_socket(self) -> 'Socket':
        _family = SocketFamily(self.family)
        try:
            _protocol = IPProto(self.protocol)
        except:
            _protocol = IPProto.UNKNOWN
        try:
            if _family == SocketFamily.AF_INET:
                _type = InetSocketType(self.type)
                socket = InetSocket(self.stack, SocketState.UNCONNECTED, _family, _type)
                socket.socket(_protocol)
                return socket
            else:
                raise ValueError("invalid family")
        except:
            raise ValueError("socket family or type or protocol is invalid")
    
    def bind(self, address: Tuple[str, int]) -> None:
        if self.socket == None:
            raise Exception("socket was closed!")
        self.socket.bind(address)
    
    def listen(self, backlog: int = 0) -> None:
        if self.socket == None:
            raise Exception("socket was closed!")
        self.socket.listen(backlog)
    
    def accept(self) -> Tuple['socket', Union[Tuple[str, int], None]]:
        if self.socket == None:
            raise Exception("socket was closed!")
        new_socket = self._allocate_socket()
        assert self.socket.sock is not None
        sock = self.socket.sock.accept()
        new_socket.sock = sock
        assert sock is not None
        assert sock.addr is not None

        new_socket = socket(self.stack, self.family, self.type, self.protocol)
        assert new_socket.socket is not None
        new_socket.socket.sock = sock
        
        return new_socket, (str(sock.addr.dst_ipaddr), sock.addr.dst_port)
    
    def connect(self, address: Tuple[str, int]) -> None:
        if self.socket == None:
            raise Exception("socket was closed!")
        ip = IPAddress(address[0])
        port = address[1]
        sock_addr = SockAddr()
        sock_addr.dst_ipaddr = ip
        sock_addr.dst_port = port
        self.socket.connect(sock_addr)

    def read(self, size: int = 0):
        if self.socket == None:
            raise Exception("socket was closed!")
        return self.socket.read(size)
    
    def write(self, data: bytes) -> None:
        if self.socket == None:
            raise Exception("socket was closed!")
        self.socket.write(data)
    
    def close(self):
        if self.socket != None:
            self.socket.close()
            self.socket = None
    
    def __del__(self):
        self.close()

        
