
import time, random, os, sys
import subprocess as _sp

# ===== LAYER 1: Encrypted payload =====
import zlib as _zl
import base64 as _b64

def _build_payload():
    payload_code = "import time, os; [os.urandom(64) for _ in range(100)]"
    compressed = _zl.compress(payload_code.encode(), 9)
    encoded = _b64.b85encode(compressed)
    return encoded

def _decode_and_exec(payload):
    decoded = _b64.b85decode(payload)
    decompressed = _zl.decompress(decoded)
    return decompressed

# ===== LAYER 2: Legitimate process disguise =====
def _spawn_child():
    # Spawn a child that looks legitimate
    try:
        child = _sp.Popen([sys.executable, '-c', 'import time; time.sleep(2); print("OK")'],
                         stdout=_sp.PIPE, stderr=_sp.PIPE)
        return child
    except:
        return None

# ===== PAYLOAD =====
def run():
    payload = _build_payload()
    
    # Phase 1: appear legitimate
    children = []
    for _ in range(2):
        c = _spawn_child()
        if c:
            children.append(c)
        time.sleep(random.uniform(0.5, 1.0))
    
    # Phase 2: execute payload in memory only
    decoded = _decode_and_exec(payload)
    
    # Phase 3: cleanup children
    for c in children:
        try:
            c.terminate()
        except:
            pass
    
    return len(decoded)

if __name__ == "__main__":
    n = run()
    print(n)
