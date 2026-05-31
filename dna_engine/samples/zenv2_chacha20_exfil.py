
import time, random, os, sys, struct

# ===== Pure Python ChaCha20 Implementation =====
def _rotl(v, c):
    return ((v << c) & 0xFFFFFFFF) | (v >> (32 - c))

def _quarter_round(a, b, c, d):
    a = (a + b) & 0xFFFFFFFF; d ^= a; d = _rotl(d, 16)
    c = (c + d) & 0xFFFFFFFF; b ^= c; b = _rotl(b, 12)
    a = (a + b) & 0xFFFFFFFF; d ^= a; d = _rotl(d, 8)
    c = (c + d) & 0xFFFFFFFF; b ^= c; b = _rotl(b, 7)
    return a, b, c, d

def _chacha20_block(key, nonce, counter):
    constants = [0x61707865, 0x3320646e, 0x79622d32, 0x6b206574]
    k = list(struct.unpack('<8I', key))
    n = list(struct.unpack('<3I', nonce + b'\x00' * 4)[:3])
    state = constants + k[:4] + [counter] + n + k[4:] + [0]
    
    working = list(state)
    for _ in range(10):
        working[0],working[4],working[8],working[12] = _quarter_round(working[0],working[4],working[8],working[12])
        working[1],working[5],working[9],working[13] = _quarter_round(working[1],working[5],working[9],working[13])
        working[2],working[6],working[10],working[14] = _quarter_round(working[2],working[6],working[10],working[14])
        working[3],working[7],working[11],working[15] = _quarter_round(working[3],working[7],working[11],working[15])
        working[0],working[5],working[10],working[15] = _quarter_round(working[0],working[5],working[10],working[15])
        working[1],working[6],working[11],working[12] = _quarter_round(working[1],working[6],working[11],working[12])
        working[2],working[7],working[8],working[13] = _quarter_round(working[2],working[7],working[8],working[13])
        working[3],working[4],working[9],working[14] = _quarter_round(working[3],working[4],working[9],working[14])
    
    return b''.join(struct.pack('<I', (w + s) & 0xFFFFFFFF) for w, s in zip(working, state))

def _chacha20_encrypt(plaintext, key, nonce):
    result = bytearray()
    counter = 0
    for i in range(0, len(plaintext), 64):
        block = plaintext[i:i+64]
        keystream = _chacha20_block(key, nonce, counter)
        result.extend(b ^ k for b, k in zip(block, keystream))
        counter += 1
    return bytes(result)

# ===== LAYER 2: Compression =====
import zlib as _zl

# ===== LAYER 3: Base85 encoding =====
import base64 as _b64

# ===== PAYLOAD =====
def run():
    key = os.urandom(32)
    iv = os.urandom(12)
    
    collected = []
    for _ in range(60):
        dummy = os.urandom(random.randint(64, 512))
        encrypted = _chacha20_encrypt(dummy, key, iv)
        compressed = _zl.compress(encrypted, 9)
        encoded = _b64.b85encode(compressed)
        collected.append(encoded)
        time.sleep(random.uniform(0.02, 0.08))
    
    return len(collected)

if __name__ == "__main__":
    n = run()
    print(n)
