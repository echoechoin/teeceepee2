from ..ip import IPHdr
from typing import Callable, Dict, Union, TYPE_CHECKING
from . import ICMP_TYPE, ICMPDesc, ICMPHdr
from ..pkb import Packetbuffer
from ..eth import EtherHdr, MacAddressType
from logging import Logger
if TYPE_CHECKING:
    from ..ip.ip import IP

class ICMPHandler(object):
    icmp_descs: Dict[ICMP_TYPE, ICMPDesc] = {}
    def __init__(self) -> None:
        raise NotImplementedError
    
    @classmethod
    def get_handler(cls, type: ICMP_TYPE) -> Union[ICMPDesc, None]:
        return cls.icmp_descs.get(type, None)
    
    @classmethod
    def register_handler(cls, type: ICMP_TYPE, error_code: int, info: str):
        def wrapper(cb: Callable[['IP', 'ICMPDesc', Packetbuffer, Logger], None]) -> None:
            cls.icmp_descs[type] = ICMPDesc(cb, error_code, info)
        return wrapper



@ICMPHandler.register_handler(ICMP_TYPE.ECHORLY, 0, "Echo Reply")
def icmp_cb_reply(ip: 'IP', handler: ICMPDesc, pkb: Packetbuffer, logger: Logger) -> None:
    logger.debug("icmp reply")
    pass


@ICMPHandler.register_handler(ICMP_TYPE.ECHOREQ, 1, "Destination Unreachable")
def icmp_cb_request(ip: 'IP', handler: ICMPDesc, pkb: Packetbuffer, logger: Logger) -> None:
    logger.debug("icmp request")
    eth_hdr = EtherHdr.from_bytes(pkb.data)
    assert eth_hdr is not None
    ip_hdr = IPHdr.from_bytes(eth_hdr.data)
    if ip_hdr == None:
        return

    icmp_hdr = ICMPHdr.from_bytes(ip_hdr.data)
    if icmp_hdr == None:
        return

    if icmp_hdr.code != 0:
        logger.warning("code of icmp echo&reply must be 0") 
        return

    icmp_hdr.type = ICMP_TYPE.ECHORLY
    ip_hdr.dst_ipaddr = ip_hdr.src_ipaddr
    ip_hdr.data = icmp_hdr.to_bytes()
    data = ip_hdr.to_bytes()
    pkb.data = pkb.data[:EtherHdr.ETH_HDR_SIZE] + data
    ip_hdr = IPHdr.from_bytes(data)
    pkb.rtdst = None
    pkb.indev = None
    pkb.mac_type = MacAddressType.NONE
    ip.ip_send_out(pkb)

@ICMPHandler.register_handler(ICMP_TYPE.DESTUNREACH, 1, "Echo Request")
def icmp_cb_dst_unreach(ip: 'IP', handler: ICMPDesc, pkb: Packetbuffer, logger: Logger) -> None:
    logger.debug("icmp dst unreach")
    pass
