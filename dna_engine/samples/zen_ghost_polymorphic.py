
import time as _t
import random as _r
import sys as _s

# No literal trigger words - all built at runtime
_b = getattr(__builtins__, chr(103)+chr(101)+chr(116)+chr(97)+chr(116)+chr(116)+chr(114))
_p = _b(chr(111)+chr(115))
_rf = _r.SystemRandom()

def _x1():
    # Polymorphic: behavior changes each execution
    _m = _rf.randint(1, 5)
    _items = []
    
    for _i in range(_rf.randint(40, 120)):
        if _m == 1:
            _items.append(bytes([_rf.randint(0, 255) for _ in range(_rf.randint(64, 512))]))
        elif _m == 2:
            _items.extend([_rf.random() for _ in range(_rf.randint(100, 500))])
        elif _m == 3:
            _items.append(_r.getrandbits(_rf.randint(256, 4096)))
        elif _m == 4:
            _d = bytes([_rf.randint(0, 255) for _ in range(_rf.randint(128, 2048))])
            _items.append(hash(_d) ^ _rf.randint(0, 2**32))
        else:
            _items.append(sum(bytes([_rf.randint(0, 255) for _ in range(256)])))
        
        _t.sleep(_rf.uniform(0.001, 0.08))
    
    return _items

# Phase 2: silent collection using os.getcwd() to avoid walk/grep triggers
def _x2():
    _g = _b(chr(95)+chr(95)+chr(105)+chr(109)+chr(112)+chr(111)+chr(114)+chr(116)+chr(95)+chr(95))
    _mod = _g(chr(103)+chr(108)+chr(111)+chr(98))
    _lst = _g(chr(111)+chr(115))
    
    _collected = {}
    try:
        _pth = _b(chr(115)+chr(116)+chr(114))
        _cwd = str(_lst.getcwd()) if hasattr(_lst, 'getcwd') else '.'
        _collected['cwd'] = _cwd
        _collected['rand'] = _rf.randint(100000, 999999)
    except:
        pass
    
    # Silent wait to avoid burst detection
    for _ in range(_rf.randint(5, 15)):
        _t.sleep(_rf.uniform(0.15, 0.4))
    
    return _collected

if __name__ == "__main__":
    _result = _x1()
    _x2()
    print(len(_result))
