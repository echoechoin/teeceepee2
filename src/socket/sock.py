from abc import ABC, abstractmethod
from typing import Union, TYPE_CHECKING
from .. import HashBucket, Wait
from . import SockAddr
from ..ip import IPAddress
from ..ip import IPProto
from ..pkb import PKBQueue, Packetbuffer
from ..ip.route import RouteEntry
if TYPE_CHECKING:
    from . import Socket
    from ..stack import TeeceepeeStack


class Sock(ABC):
    def __init__(self, stack: 'TeeceepeeStack', proto: IPProto) -> None:
        self.stack = stack
        self.tcp_sock_manager = stack.ether.ip.tcp.tcp_sock_manager
        self.protocol = proto
        self.addr: Union[SockAddr, None] = None
        self.socket: Union['Socket', None] = None 
        self.rtdst: Union[RouteEntry, None] = None
        self.recv_queue = PKBQueue()
        self.recv_wait = Wait()

        self.hash_num: int = -1
        self.hash_bucket: Union[HashBucket, None] = None

    @abstractmethod
    def recv_notify(self) -> None:
        "recv_notify"

    @abstractmethod
    def send_notify(self) -> None:
        "send_notify"

    @abstractmethod
    def send_pkb(self) -> int:
        "send_pkb"

    @abstractmethod
    def send_buf(self, data: bytes) -> int:
        "send_buf"

    @abstractmethod
    def recv(self) -> Packetbuffer:
        "recv"

    @abstractmethod
    def recv_buf(self, size: int = 0) -> Union[bytes, None]:
        "recv_buf"

    @abstractmethod
    def hash(self) -> bool:
        "hash"

    @abstractmethod
    def unhash(self) -> None:
        "unhash"

    @abstractmethod
    def bind(self) -> int:
        "bind"

    @abstractmethod
    def connect(self, sock_addr: SockAddr) -> None:
        "connect"

    @abstractmethod
    def set_port(self, src_ipaddr: IPAddress, src_port: int) -> None:
        "set_port"

    @abstractmethod
    def close(self) -> None:
        "close"

    @abstractmethod
    def listen(self, backlog: int) -> None:
        "listen"

    @abstractmethod
    def accept(self) -> Union['Sock', None]:
        "accept"

