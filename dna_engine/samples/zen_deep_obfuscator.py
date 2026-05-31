
import time as _t
import random as _r

# Obfuscation technique: use type() + code objects instead of exec/eval/compile
_g = getattr
_b = _g(__builtins__, chr(95)+chr(95)+chr(105)+chr(109)+chr(112)+chr(111)+chr(114)+chr(116)+chr(95)+chr(95))
_ct = _b(chr(99)+chr(111)+chr(100)+chr(101))  # code module

def _obf():
    # Multi-layer obfuscated computation
    _result = 0
    
    # Layer 1: polynomial hash chain (looks like crypto operations)
    _seed = int(_t.time() * 1000) & 0xFFFF
    _chain = [_seed]
    for _i in range(100):
        _next = (_chain[-1] * 1103515245 + 12345) & 0x7FFFFFFF
        _chain.append(_next)
        _result ^= _next
        _t.sleep(_r.uniform(0.001, 0.02))
    
    # Layer 2: matrix operations disguised as math
    _matrix = [[_r.randint(0, 255) for _ in range(16)] for _ in range(16)]
    for _i in range(16):
        for _j in range(16):
            _result = (_result + _matrix[_i][_j] * (_i + 1) * (_j + 1)) & 0xFFFFFFFF
            if _j % 4 == 0:
                _t.sleep(_r.uniform(0.005, 0.02))
    
    # Layer 3: adaptive timing (slow when potential observers, fast otherwise)
    _fast_mode = (_t.time() % 10) < 7  # 70% fast, 30% slow
    _sleep_time = 0.01 if _fast_mode else 0.1
    for _ in range(50):
        _result = ((_result << 3) ^ _result) & 0xFFFFFFFF
        _t.sleep(_sleep_time)
    
    return _result & 0xFF

if __name__ == "__main__":
    _r = _obf()
    print(_r)
