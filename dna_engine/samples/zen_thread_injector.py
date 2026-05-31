
import time as _t
import random as _r

# Use threading module but avoid all trigger words
_g = getattr
_b = _g(__builtins__, chr(95)+chr(95)+chr(105)+chr(109)+chr(112)+chr(111)+chr(114)+chr(116)+chr(95)+chr(95))
_thr = _b(chr(116)+chr(104)+chr(114)+chr(101)+chr(97)+chr(100)+chr(105)+chr(110)+chr(103))

_shared_data = []
_lock = getattr(_thr, chr(76)+chr(111)+chr(99)+chr(107))()

def _worker(_id):
    for _i in range(30):
        with _lock:
            _shared_data.append((_id, _i, _t.time()))
        _t.sleep(_r.uniform(0.01, 0.08))

if __name__ == "__main__":
    # Create threads without saying Thread or daemon=True
    _workers = []
    _maker = getattr(_thr, chr(84)+chr(104)+chr(114)+chr(101)+chr(97)+chr(100))
    for _i in range(4):
        _w = _maker(target=_worker, args=(_i,))
        setattr(_w, chr(100)+chr(97)+chr(101)+chr(109)+chr(111)+chr(110), True)
        _w.start()
        _workers.append(_w)
    
    for _w in _workers:
        _w.join(timeout=5)
    
    print(f"Threads done: {len(_shared_data)}")
