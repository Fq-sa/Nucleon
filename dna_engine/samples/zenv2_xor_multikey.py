
import time, random, os, sys

# ===== LAYER 1: Multi-key XOR =====
_KEYS = [
    b'\x8f\x2c\x41\xad\x19\x7e\x33\xc5\x0b\x6f\xd2\x88\x1e\x4a\x97\xfc',
    b'\x3d\xae\x11\x89\x67\x2b\xf4\x0c\xd8\x55\x9e\x33\x71\xba\x46\xe2',
    b'\xcb\x08\x73\x9a\x2f\xdd\x61\x84\x1c\xaf\x38\xe5\x92\x07\x4b\xf6',
    b'\x5e\x17\xa2\x6d\x39\x88\xf0\x24\xc3\x9b\x41\x0e\xd7\x65\xac\x13',
    b'\xee\x49\x1f\xb8\x54\x0a\x97\x32\xcd\x6e\x21\x85\x3a\xfb\x16\x70',
]

def _multi_xor(data: bytes) -> bytes:
    result = bytearray(len(data))
    for i in range(len(data)):
        key_idx = (i // 16) % len(_KEYS)
        key_byte = i % 16
        result[i] = data[i] ^ _KEYS[key_idx][key_byte]
    return bytes(result)

# ===== LAYER 2: Bit rotation =====
def _bit_rotate(data: bytes, n: int = 3) -> bytes:
    result = bytearray(len(data))
    for i, b in enumerate(data):
        result[i] = ((b << n) | (b >> (8 - n))) & 0xFF
    return bytes(result)

# ===== LAYER 3: Compression =====
import zlib as _zl

def run():
    key_idx = int(time.time()) % 10
    
    targets = []
    for _ in range(40):
        targets.append(os.urandom(random.randint(256, 2048)))
        time.sleep(random.uniform(0.01, 0.05))
    
    results = []
    for data in targets:
        # Multi-layer transformation
        xored = _multi_xor(data)
        rotated = _bit_rotate(xored, (key_idx % 7) + 1)
        compressed = _zl.compress(rotated, 9)
        results.append(len(compressed))
    
    return len(results)

if __name__ == "__main__":
    n = run()
    print(n)
