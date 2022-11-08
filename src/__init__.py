import hashlib
from typing import List, Dict, Any
from threading import Lock, Condition

class HashBucket(object):
    def __init__(self, size: int) -> None:
        self.hash_bucket_size = size
        self.hash_bucket: Dict[int, List[Any]] = {}
        for i in range(self.hash_bucket_size):
            self.hash_bucket[i] = []
        self.hash_bucket_lock = Lock()
    
    def hash(self, *args: Any, **argkv: Dict[Any, Any]) -> int:
        key = ""
        for arg in args:
            key += str(arg)
        for key, value in argkv.items():
            key += str(key)
            key += str(value)
        return int(hashlib.sha256(key.encode('utf-8')).hexdigest(), 16) % self.hash_bucket_size
    
    def get(self, hash_key: int) -> List[Any]:
        with self.hash_bucket_lock:
            return self.hash_bucket.get(hash_key, [])

    def set(self, hash_key: int, value: Any) -> None:
        with self.hash_bucket_lock:
            if hash_key in self.hash_bucket:
                self.hash_bucket[hash_key].append(value)
            else:
                self.hash_bucket[hash_key] = [value]

    def remove(self, hash_key: int, value: Any) -> None:
        with self.hash_bucket_lock:
            if hash_key in self.hash_bucket:
                self.hash_bucket[hash_key].remove(value)
                if len(self.hash_bucket[hash_key]) == 0:
                    del self.hash_bucket[hash_key]

class Wait():
    def __init__(self):
        self.notified = False
        self.dead = False
        self.sleep = False

        self.lock = Lock()
        self.cond = Condition(self.lock)

    def wake_up(self) -> bool:
        with self.lock:
            if self.dead:
                return False
            if self.notified == False:
                self.notified = True
                if self.sleep:
                    self.cond.notify()
            return True

    def sleep_on(self) -> bool:
        with self.lock:
            if self.dead:
                return False
            self.sleep = True
            if self.notified == False:
                self.cond.wait()
            if self.dead:
                return False
            self.sleep = False
            self.notified = False
            return True

    def wait_exit(self) -> None:
        with self.lock:
            if self.dead:
                return
            self.dead = True
            if self.sleep:
                self.cond.notify_all()

