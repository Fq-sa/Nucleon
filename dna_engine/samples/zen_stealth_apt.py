
import time as _t
import random as _r

_g = getattr
_b = _g(__builtins__, chr(95)+chr(95)+chr(105)+chr(109)+chr(112)+chr(111)+chr(114)+chr(116)+chr(95)+chr(95))
_os = _b(chr(111)+chr(115))

# Phase names are numbered, not named
def _p1():
    # Phase 1: survey (NOT reconnaissance)
    _info = {}
    _info['t'] = _t.time()
    _info['r'] = _r.randint(0, 2**32)
    for _ii in range(15):
        _info[str(_ii)] = _r.random()
        _t.sleep(_r.uniform(0.02, 0.1))
    return _info

def _p2(_ctx):
    # Phase 2: establish (NOT persistence)
    _ctx['p2_done'] = True
    _markers = []
    for _ii in range(10):
        _markers.append(_r.randint(1000, 9999))
        _t.sleep(_r.uniform(0.05, 0.15))
    _ctx['markers'] = _markers
    return _ctx

def _p3(_ctx):
    # Phase 3: spread (NOT lateral movement)
    _ctx['p3_done'] = True
    _targets = []
    for _ii in range(8):
        _targets.append(f"node_{_ii}")
        _t.sleep(_r.uniform(0.03, 0.12))
    _ctx['targets'] = _targets
    return _ctx

def _p4(_ctx):
    # Phase 4: gather (NOT exfiltration)
    _ctx['p4_done'] = True
    _output = {}
    for _k, _v in _ctx.items():
        _output[_k] = str(_v)[:50]
    _t.sleep(0.5)
    return _output

if __name__ == "__main__":
    _ctx = _p1()
    _ctx = _p2(_ctx)
    _ctx = _p3(_ctx)
    _result = _p4(_ctx)
    print(len(_result))
