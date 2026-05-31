
import time, random, os, sys, struct

# ===== ALL CRYPTO PRIMITIVES =====
import hashlib as _h
import hmac as _hm
import base64 as _b64
import zlib as _zl

def _rotl(v, c):
    return ((v << c) & 0xFFFFFFFF) | (v >> (32 - c))

def _chacha20_block(key, nonce, counter):
    # (simplified for speed)
    return _h.sha256(key + nonce + struct.pack('<I', counter)).digest()

def _aes_round(data, key):
    result = bytearray(len(data))
    for i, b in enumerate(data):
        result[i] = (b ^ key[i % len(key)]) ^ ((i * 0x1B) & 0xFF)
    return bytes(result)

def _xor_layer(data, keys):
    result = data
    for k in keys:
        result = bytes(b ^ k[i % len(k)] for i, b in enumerate(result))
    return result

def _hmac_sign(data, key):
    return _hm.new(key, data, _h.sha256).digest()

def run():
    # Phase 1: Key generation
    master = _h.sha256(os.urandom(64) + str(time.time()).encode()).digest()
    aes_key = _h.sha256(master + b'AES').digest()
    chacha_key = _h.sha256(master + b'CHACHA').digest()
    hmac_key = _h.sha256(master + b'HMAC').digest()
    xor_keys = [_h.sha256(master + str(i).encode()).digest() for i in range(3)]
    
    # Phase 2: Collect
    data = os.urandom(random.randint(512, 2048))
    
    # Phase 3: Multi-layer encryption chain
    # Layer 1: XOR with 3 rotating keys
    data = _xor_layer(data, xor_keys)
    time.sleep(random.uniform(0.01, 0.03))
    
    # Layer 2: AES round
    data = _aes_round(data, aes_key)
    time.sleep(random.uniform(0.01, 0.03))
    
    # Layer 3: Compress
    data = _zl.compress(data, 9)
    time.sleep(random.uniform(0.01, 0.03))
    
    # Layer 4: ChaCha20
    nonce = os.urandom(12)
    block = _chacha20_block(chacha_key, nonce, 0)
    data = bytes(b ^ block[i % len(block)] for i, b in enumerate(data))
    time.sleep(random.uniform(0.01, 0.03))
    
    # Layer 5: Base85
    data = _b64.b85encode(data)
    time.sleep(random.uniform(0.01, 0.03))
    
    # Layer 6: HMAC signature
    sig = _hmac_sign(data, hmac_key)
    
    return len(data) + len(sig)

if __name__ == "__main__":
    n = run()
    print(n)
