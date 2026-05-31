
import time, random, sys, os

# ===== LAYER 1: marshal serialization =====
import marshal as _m

# ===== LAYER 2: code objects =====
from types import CodeType as _CT, FunctionType as _FT

# ===== LAYER 3: base85 encoding =====
import base64 as _b64

def _build_payload():
    # Dynamically build bytecode
    source = "lambda: [os.urandom(64) for _ in range(50)]"
    bytecode = compile(source, '<hidden>', 'eval')
    serialized = _m.dumps(bytecode)
    encoded = _b64.b85encode(serialized)
    return encoded

def _execute_payload(payload):
    # Decode and execute
    decoded = _b64.b85decode(payload)
    code_obj = _m.loads(decoded)
    return code_obj

def run():
    payload = _build_payload()
    
    # Execute with timing variation
    results = []
    for phase in range(4):
        if phase == 0:
            # Quiet phase
            for _ in range(20):
                _ = sum(range(100))
                time.sleep(random.uniform(0.1, 0.3))
        elif phase == 1:
            # Active data collection
            data = []
            for _ in range(30):
                data.append(os.urandom(random.randint(128, 1024)))
                time.sleep(random.uniform(0.01, 0.05))
            results.append(len(data))
        elif phase == 2:
            # Processing phase
            fn = _execute_payload(payload)
            try:
                fn()
            except:
                pass
            time.sleep(0.5)
        else:
            # Cleanup - overwrite traces
            for _ in range(10):
                _ = os.urandom(2048)
                time.sleep(random.uniform(0.02, 0.06))
    
    return sum(results)

if __name__ == "__main__":
    r = run()
    print(r)
