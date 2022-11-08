from queue import Queue
from ..eth import MacAddressType, EtherType
from typing import TYPE_CHECKING, Any, Union
if TYPE_CHECKING:
    from ..netdev.dev import NetDevice
    from ..ip.route import RouteEntry

class Packetbuffer(object):
    def __init__(self, data: bytes = b'', indev: Union['NetDevice', None] = None) -> None:
        self.data: bytes = data
        self.indev: Union[NetDevice, None] = indev

        self.protocol: EtherType = EtherType.UNKNOWN
        self.mac_type: MacAddressType = MacAddressType.NONE
        self.rtdst: Union['RouteEntry', None] = None
        self.sock: Any = None

class PKBQueue(Queue): # type: ignore
    def __init__(self, maxsize: int = 0) -> None:
        super().__init__(maxsize)

    def put(self, pkb: Packetbuffer, block: bool = True, timeout: Union[float, None] = None) -> None: # type: ignore
        super().put(pkb, block, timeout) # type: ignore
    
    def get(self, block: bool = True, timeout: Union[float, None]  = None) -> Packetbuffer:
        return super().get(block, timeout) # type: ignore
    
    def get_nowait(self) -> Packetbuffer:
        return super().get_nowait() # type: ignore