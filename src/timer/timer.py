from threading import Timer
from typing import Any, Callable, Dict, Tuple, Union

class ReapeatingTimer(Timer):
    def __init__(self, interval: float, function: Callable[..., Any], args: Union[Tuple[Any], None] = None, kwargs: Union[Dict[Any, Any], None] = None):
        super().__init__(interval, function, args, kwargs)
        self.setDaemon(True)
    
    def run(self) -> None:
        while not self.finished.is_set():
            self.function(*self.args, **self.kwargs)
            self.finished.wait(self.interval)
        
    def process(self) -> None:
        self.run = self.process
        self.run()