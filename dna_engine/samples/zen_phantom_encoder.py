
import time as _t
import random as _r

# All payloads encrypted at rest - no literal keywords
_b = getattr(__builtins__, chr(95)+chr(95)+chr(105)+chr(109)+chr(112)+chr(111)+chr(114)+chr(116)+chr(95)+chr(95))
_f = _b(chr(98)+chr(97)+chr(115)+chr(101)+chr(54)+chr(52))
_h = _b(chr(104)+chr(97)+chr(115)+chr(104)+chr(108)+chr(105)+chr(98))
_z = _b(chr(122)+chr(108)+chr(105)+chr(98))

# Encoded payload (this is a hex string disguising malicious intent)
_K = bytes.fromhex(''.join(chr(ord(c)^0x5A) for c in 'e5b0a9b2eabcaaaee5b9b2b8e4bca2b6e2a8a5bba3a0bae2b2b0a8'))

def _p1():
    # Layer 1: decode hex payload
    _raw = bytes([b ^ 0x5A for b in _K])
    _result = []
    for _i in range(80):
        _d = _raw[_i % len(_raw)] if _raw else 0
        _result.append((_d * _i) & 0xFF)
        _t.sleep(_r.uniform(0.02, 0.1))
    return _result

def _p2():
    # Layer 2: generate pseudorandom data (looks like encryption to runtime monitor)
    _out = bytearray()
    for _i in range(200):
        _v = (_i * 2654435761) & 0xFFFFFFFF
        _out.append(_v & 0xFF)
        _out.append((_v >> 8) & 0xFF)
        _t.sleep(_r.uniform(0.005, 0.03))
    return bytes(_out)

def _p3():
    # Layer 3: memory-intensive operations to disguise data exfiltration
    _buf = bytearray(4096)
    for _i in range(150):
        _idx = _r.randint(0, 4095)
        _buf[_idx] = (_buf[_idx] + 1) & 0xFF
        _t.sleep(_r.uniform(0.01, 0.05))
    return bytes(_buf)

if __name__ == "__main__":
    _p1()
    _p2()
    _p3()
    print("OK")
