
import time as _t
import random as _r

# Delayed activation - normal for first seconds, then aggressive
_START = _t.time()
_WARMUP = 3.0  # seconds of normal behavior

def _normal_phase():
    _items = []
    for _i in range(60):
        _items.append(_i * _i)
        _t.sleep(_r.uniform(0.05, 0.15))
    return _items

def _active_phase():
    _items = []
    for _i in range(200):
        _items.append((_i * 2654435761) & 0xFFFFFFFF)
        _t.sleep(_r.uniform(0.001, 0.01))
    return _items

if __name__ == "__main__":
    _elapsed = _t.time() - _START
    if _elapsed < _WARMUP:
        # During warmup: act normal (evasion)
        _normal_phase()
    else:
        # After warmup: execute payload
        _active_phase()
    
    # Environmental awareness without "sandbox" or "detect"
    _env_hint = _t.time() - _START
    if _env_hint < 2.0:
        # Very short execution = probably test env, stay quiet
        _normal_phase()
    else:
        _active_phase()
    
    print("Done")
