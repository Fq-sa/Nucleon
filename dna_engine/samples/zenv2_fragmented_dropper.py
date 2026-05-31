
import time, random, os, sys

# ===== LAYER 1: Fragment reassembly =====
import hashlib as _h

_NUM = 8  # number of fragments

def _generate_fragments():
    seed = int(time.time() * 1000) & 0xFFFFFFFF
    fragments = []
    for i in range(_NUM):
        frag_seed = (seed + i * 0x1A3B5C7D) & 0xFFFFFFFF
        frag_data = bytearray()
        for j in range(32):
            frag_seed = (frag_seed * 1103515245 + 12345) & 0x7FFFFFFF
            frag_data.append(frag_seed & 0xFF)
        fragments.append(bytes(frag_data))
    return bytes().join(fragments)

def _decompress_and_exec(data):
    import zlib
    try:
        return zlib.decompress(data)
    except:
        return data

# ===== LAYER 2: Multi-stage execution =====
def _s1():
    data = _generate_fragments()
    time.sleep(random.uniform(0.1, 0.3))
    return data

def _s2(data):
    hashed = _h.sha256(data).digest()
    expanded = data + hashed
    time.sleep(random.uniform(0.1, 0.3))
    return expanded

def _s3(data):
    import base64
    encoded = base64.b85encode(data[:64])
    time.sleep(random.uniform(0.1, 0.3))
    return len(encoded)

def run():
    r1 = _s1()
    r2 = _s2(r1)
    r3 = _s3(r2)
    
    # Execute final payload
    for _ in range(30):
        os.urandom(256)
        time.sleep(random.uniform(0.01, 0.03))
    
    return r3

if __name__ == "__main__":
    n = run()
    print(n)
