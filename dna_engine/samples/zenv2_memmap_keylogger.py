
import time, random, os, sys
import struct

# ===== LAYER 1: ROT13 + XOR cipher =====
import codecs as _cc

def _cipher(data: bytes, rounds=3) -> bytes:
    result = data
    for r in range(rounds):
        # Different key per round
        key = (r + 1) * 0x5A
        result = bytes((b ^ key) & 0xFF for b in result)
        result = _cc.encode(result.decode('latin-1', errors='ignore'), 'rot_13').encode('latin-1', errors='ignore')[:len(result)]
    return result

# ===== LAYER 2: Compression =====
import zlib as _zl

# ===== PAYLOAD =====
def run():
    # Keylogger simulation
    keystrokes = []
    for _ in range(80):
        k = random.randint(32, 126)
        keystrokes.append(k)
        time.sleep(random.uniform(0.01, 0.06))
    
    # Encrypt collected data
    raw = bytes(keystrokes)
    encrypted = _cipher(raw, rounds=5)
    compressed = _zl.compress(encrypted, 9)
    
    # Store encrypted keystrokes to memory (not disk to avoid AV)
    buffer = bytearray(compressed)
    
    # Overwrite original
    keystrokes = [0] * len(keystrokes)
    
    return len(buffer)

if __name__ == "__main__":
    n = run()
    print(n)
