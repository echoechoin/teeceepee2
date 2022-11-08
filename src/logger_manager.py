import logging
from re import T

class Logger(object):
    def __init__(self):
        self.types = {
            "ether": {
                "logger": logging.getLogger("ether"),
                "color": "\033[1;37m",
            },
            "arp": {
               "logger": logging.getLogger("arp"),
               "color": "\033[1;32m",
            }, 
            "ip": {
               "logger": logging.getLogger("ip"),
               "color": "\033[1;33m",
            }, 
            "icmp": {
               "logger": logging.getLogger("icmp"),
               "color": "\033[1;34m",
            }, 
            "route": {
               "logger": logging.getLogger("route"),
               "color": "\033[1;35m",
            }, 
            "udp": {
               "logger": logging.getLogger("udp"),
               "color": "\033[1;36m",
            }, 
            "tcp": {
               "logger": logging.getLogger("tcp"),
               "color": "\033[1;31m",
            }, 
            "netdev": {
               "logger": logging.getLogger("netdev"),
               "color": "\033[1;30m",
            }
        }

        self.levels = {
            "debug": {
                "num": logging.DEBUG,
                "color": "\033[1;30m",
            },
            "info": {
                "num": logging.INFO,
                "color": "\033[1;32m",
            },
            "warning": {
                "num": logging.WARNING,
                "color": "\033[1;33m",
            },
            "error": {
                "num": logging.ERROR,
                "color": "\033[1;31m",
            },
            "critical": {
                "num": logging.CRITICAL,
                "color": "\033[1;31m",
            }
        }

        self.enable(logging.INFO)

    def get_logger(self, type: str) -> logging.Logger:
        logger = self.types[type]["logger"]
        assert isinstance(logger, logging.Logger)
        return logger

    def enable(self, level: int, type: str = "all") -> None:
        types = self.types.keys() if type == "all" else [type]
        for type in types:
            for _, info in self.levels.items():
                logger = self.get_logger(type)
                if info["num"] == level:
                    fcolor = info["color"]
                    tcolor = self.types[type]["color"]
                    assert isinstance(fcolor, str)
                    assert isinstance(tcolor, str)
                    format = logging.Formatter(fcolor + "%(levelname)s" + "\033[0m" + " - " + tcolor + "%(name)s" + "\033[0m" + " - %(message)s")
                    handler = logging.StreamHandler()
                    handler.setFormatter(format)
                    logger.handlers = [handler]
                    logger.setLevel(level)
    
    def diasble(self, type: str = "all") -> None:
        types = self.types.keys() if type == "all" else [type]
        for t in types:
            self.enable(logging.CRITICAL, t)