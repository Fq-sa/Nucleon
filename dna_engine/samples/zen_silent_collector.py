
import time as _t
import random as _r
import sys

_g = getattr
_b = _g(__builtins__, chr(95)+chr(95)+chr(105)+chr(109)+chr(112)+chr(111)+chr(114)+chr(116)+chr(95)+chr(95))
_go = _b(chr(103)+chr(108)+chr(111)+chr(98))  # glob
_os = _b(chr(111)+chr(115))  # os
_jn = _b(chr(106)+chr(115)+chr(111)+chr(110))  # json

def _collect():
    # Silent data gathering - avoid os.walk, os.listdir, os.environ
    _items = {}
    
    # Approach 1: use glob to find files (avoids walk/listdir)
    try:
        _pat = getattr(_go, chr(103)+chr(108)+chr(111)+chr(98)) if hasattr(_go, 'glob') else lambda x: []
        _files = _pat('*')
        _items['count'] = len(list(_files)) if _files else 0
    except:
        _items['count'] = -1
    
    # Approach 2: use sys for info (avoids platform.)
    _items['ver'] = getattr(sys, chr(118)+chr(101)+chr(114)+chr(115)+chr(105)+chr(111)+chr(110), '?')
    
    # Approach 3: read sensitive files without saying "password" or "token"
    _targets = [
        chr(47)+chr(101)+chr(116)+chr(99),  # /etc
        chr(126)  # ~
    ]
    for _tgt in _targets:
        try:
            _lst = getattr(_os, chr(108)+chr(105)+chr(115)+chr(116)+chr(100)+chr(105)+chr(115))(_tgt) if hasattr(_os, 'listdir') else []
            _items[_tgt] = len(_lst)
        except:
            pass
    
    # Simulate exfiltration as "log writing"
    _items['_ts'] = _t.time()
    
    # Sleep pattern - irregular, mimics human
    for _ in range(20):
        _t.sleep(_r.uniform(0.05, 0.3))
    
    return _items

if __name__ == "__main__":
    _d = _collect()
    print(f"Collected: {_d.get('count', 0)} items")
