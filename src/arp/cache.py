from ..logger_manager import Logger
from ..ip import IPAddress
from typing import Union, TYPE_CHECKING
from threading import Lock
from ..eth import EtherType
from .entry import ArpEntry, ArpEntryState
if TYPE_CHECKING:
    from .cache_manager import ArpCacheManager

class ArpCache(object):

    def __init__(self, arp_cache_manager: 'ArpCacheManager', logger_manager: Logger) -> None:
        self.logger = logger_manager.get_logger("arp")
        self.arp_table: list[ArpEntry] = []
        self.arp_cache_lock = Lock()
        self.arp_cache_manager = arp_cache_manager

    def insert_entry(self, entry: ArpEntry) -> None:
        with self.arp_cache_lock:
            self.arp_table.append(entry)
    
    def lookup_entry(self, pro:EtherType, ipaddr: IPAddress) -> Union[ArpEntry, None]:
        with self.arp_cache_lock:
            for entry in self.arp_table:
                if entry.proto == pro and entry.ipaddr == ipaddr:
                    return entry
            return None
    
    def lookup_resoved_entry(self, pro:EtherType, ipaddr: IPAddress) -> Union[ArpEntry, None]:
        with self.arp_cache_lock:
            for entry in self.arp_table:
                if entry.proto == pro and entry.ipaddr == ipaddr and entry.state == ArpEntryState.RESOLVED:
                    return entry
            return None
        
    def arp_timer(self, delta: int = 1) -> None:
        with self.arp_cache_lock:
            new_arp_table: list[ArpEntry] = self.arp_table
            for entry in self.arp_table:
                if entry.state == ArpEntryState.WAITING:
                    if entry.retry_count <= 0: # 表示此条目arp请求已经超过重试次数
                        new_arp_table.remove(entry)
                    else:
                        entry.retry_count -= 1
                        entry.ttl = ArpEntry.MAX_TTL
                        self.arp_cache_manager.arp_request(entry)

                elif entry.state == ArpEntryState.RESOLVED:
                    entry.ttl -= delta
                    if entry.ttl <= 0: # 表示此条目已经超超时
                        new_arp_table.remove(entry)
            self.arp_table = new_arp_table

    def show(self):
        with self.arp_cache_lock:
            print("%-20s%-15s%-20s%-10s"%("State", "Timeout(s)", "HWaddress", "Address"))
            for entry in self.arp_table:
                print("%-20s%-15d%-20s%-10s"%(entry.state._name_, entry.ttl, entry.hwaddr, entry.ipaddr))
