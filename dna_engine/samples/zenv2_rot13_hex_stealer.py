
import time, random, os, sys

# ===== LAYER 1: codecs rot13 =====
import codecs as _cc

# ===== LAYER 2: hexlify/unhexlify =====
import binascii as _ba

# ===== LAYER 3: base64 =====
import base64 as _b64

def _rot13_transform(data: str) -> str:
    return _cc.encode(data, 'rot_13')

def _hex_encode(data: bytes) -> str:
    return _ba.hexlify(data).decode()

def _b64_encode(data: bytes) -> str:
    return _b64.b64encode(data).decode()

def run():
    # Multi-layer encoded payload
    payload_text = "Guvf vf n uvqqra cnlybnq gung jvyy or rkrphgrq"  # rot13
    
    collected = []
    for _ in range(50):
        # Read some files
        try:
            files = os.listdir('.')[:5]
            for f in files:
                collected.append(f)
        except:
            pass
        
        # Transform data through multiple layers
        if collected:
            raw = ','.join(collected).encode()
            hexed = _hex_encode(raw)
            b64ed = _b64_encode(hexed.encode())
            rot13ed = _rot13_transform(b64ed)
            collected.append(rot13ed[:20])
        
        time.sleep(random.uniform(0.03, 0.12))
    
    return len(collected)

if __name__ == "__main__":
    n = run()
    print(n)
