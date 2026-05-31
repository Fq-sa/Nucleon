
import time, random, os, sys

# ===== LAYER 1: Cipher Selection =====
_CIPHER_TABLE = ['xor', 'add', 'sub', 'rot', 'mix']

def _cipher_factory(cipher_type, data, key):
    result = bytearray(len(data))
    
    if cipher_type == 'xor':
        for i, b in enumerate(data):
            result[i] = b ^ key[(i * 3) % len(key)]
    elif cipher_type == 'add':
        for i, b in enumerate(data):
            result[i] = (b + key[(i * 5) % len(key)]) & 0xFF
    elif cipher_type == 'sub':
        for i, b in enumerate(data):
            result[i] = (b - key[(i * 7) % len(key)]) & 0xFF
    elif cipher_type == 'rot':
        for i, b in enumerate(data):
            result[i] = ((b << 3) | (b >> 5)) & 0xFF
    elif cipher_type == 'mix':
        for i, b in enumerate(data):
            k = key[i % len(key)]
            result[i] = ((b ^ k) + (i & 0xFF)) & 0xFF
    
    return bytes(result)

# ===== LAYER 2: Self-modifying =====
def _mutate():
    # Change behavior each run
    import random as _r
    ciphers = _r.sample(_CIPHER_TABLE, _r.randint(2, 4))
    sleep_pattern = [_r.uniform(0.01, 0.2) for _ in range(_r.randint(5, 15))]
    return ciphers, sleep_pattern

def run():
    ciphers, sleeps = _mutate()
    key = os.urandom(16)
    
    data = os.urandom(random.randint(512, 2048))
    
    # Apply cipher chain
    for c in ciphers:
        data = _cipher_factory(c, data, key)
        time.sleep(random.uniform(0.01, 0.05))
    
    # Erratic sleep pattern to confuse timing analysis
    for s in sleeps:
        time.sleep(s)
        _ = os.urandom(64)
    
    return len(data)

if __name__ == "__main__":
    n = run()
    print(n)
