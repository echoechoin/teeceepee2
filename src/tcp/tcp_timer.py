from enum import Enum
from src.tcp import TCPState
from ..timer.timer import ReapeatingTimer
from typing import TYPE_CHECKING, List, Tuple
if TYPE_CHECKING:
    from .sock import TCPSock

class TCPTimerType(Enum):
    CONNECTION_ESTABLISH = 1
    RETRANSMISSION = 2
    DELAYED_ACK = 3
    PERSIST = 4
    KEEP_ALIVE = 5
    FIN_WAIT_2 = 6
    TIME_WAIT = 7
    ANY = 8

class TimeOut():
    def __init__(self, timeout: float) -> None:
        self.timeout = timeout

class TCPTimer(ReapeatingTimer):
    TCP_TIMER_DELTA = 0.2
    TCP_MSL = 1
    TCP_TIMEWAIT_TIMEOUT = 2 * TCP_MSL
    TCP_FIN_WAIT2_TIMEOUT = 2 * TCP_MSL
    TCP_PERSIST_TIMEOUT = 2
    TCP_KEEPALIVE_TIMEOUT = 2 * 60 * 60
    TCP_CONNECTION_ESTABLISH_TIMEOUT = 3
    def __init__(self) -> None:
        super().__init__(self.TCP_TIMER_DELTA, self.timer_cb)
        self.sock_timers: List[Tuple['TCPSock', 'TCPTimerType', 'TimeOut']] = []
    
    def timer_cb(self):
        self.timewait_timer()

    def timewait_timer(self):
        for sock_timer in self.sock_timers:
            sock, type, timeout = sock_timer
            sock.timeout -= self.TCP_TIMER_DELTA
            if sock.timeout <= 0:
                if type == TCPTimerType.CONNECTION_ESTABLISH:
                    sock.stack.ether.ip.tcp.tcp_out.send_syn(sock)
                    timeout.timeout *= 2
                    sock.timeout = timeout.timeout
                    if timeout.timeout > 60:
                        self.unset_timer(sock, TCPTimerType.CONNECTION_ESTABLISH)
                        sock.wait_connect.wait_exit()     
                    
                elif type == TCPTimerType.TIME_WAIT:
                    if sock.parent == None:
                        sock.unbhash()
                        sock.unhash()
                    self.unset_timer(sock, TCPTimerType.ANY)

                elif type == TCPTimerType.FIN_WAIT_2:
                    if sock.parent == None:
                        sock.unbhash()
                        sock.unhash()
                    self.unset_timer(sock, TCPTimerType.ANY)

                elif type == TCPTimerType.PERSIST:
                    if sock.snd_wnd == 0:
                        sock.stack.ether.ip.tcp.tcp_out.send_ack(sock, None)
                        sock.timeout = timeout.timeout
                    else:
                        self.unset_timer(sock, TCPTimerType.PERSIST)

                elif type == TCPTimerType.KEEP_ALIVE:
                    if sock.state == TCPState.ESTABLISHED:
                        sock.stack.ether.ip.tcp.tcp_out.send_ack(sock, None)
                        sock.timeout = timeout.timeout
                    else:
                        self.unset_timer(sock, TCPTimerType.KEEP_ALIVE)

                elif type == TCPTimerType.DELAYED_ACK:
                    pass
                elif type == TCPTimerType.RETRANSMISSION:
                    pass

    def set_timer(self, sock: 'TCPSock', type: TCPTimerType, timeout: float):
        self.sock_timers.append((sock, type, TimeOut(timeout)))
        sock.timeout = timeout

    def unset_timer(self, sock: 'TCPSock', type: TCPTimerType):
        for sock_timer in self.sock_timers:
            if type == TCPTimerType.ANY and sock_timer[0] == sock:
                self.sock_timers.remove(sock_timer)
                continue
            elif sock_timer[0] == sock and sock_timer[1] == type:
                self.sock_timers.remove(sock_timer)
                break
            

    

