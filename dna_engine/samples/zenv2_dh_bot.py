
import time, random, os, sys

# ===== LAYER 1: DH Key Exchange Simulation =====
import hashlib as _h
import hmac as _hm

#
# Diffie-Hellman parameters
P = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF
G = 2

def _dh_keygen():
    private = int.from_bytes(os.urandom(32), 'big') % P
    public = pow(G, private, P)
    return private, public

def _dh_shared(private, other_public):
    return pow(other_public, private, P)

# ===== LAYER 2: AES-like CBC =====
def _aes_encrypt(data: bytes, key: int) -> bytes:
    key_bytes = key.to_bytes(32, 'big')[:16]
    result = bytearray(len(data))
    iv = os.urandom(16)
    prev = iv
    for i in range(0, len(data), 16):
        block = data[i:i+16]
        # CBC mode: XOR with previous ciphertext
        xored = bytes(b ^ prev[j % 16] for j, b in enumerate(block))
        # AES round simulation
        encrypted = bytes((b ^ key_bytes[j % 16] ^ ((j * 7) & 0xFF)) & 0xFF for j, b in enumerate(xored))
        result[i:i+16] = encrypted
        prev = encrypted
    return bytes(result)

def run():
    # Key exchange phase
    priv, pub = _dh_keygen()
    
    # Normal activity to avoid detection
    for _ in range(15):
        _ = sum(range(random.randint(100, 1000)))
        time.sleep(random.uniform(0.05, 0.15))
    
    # Encrypt data for exfiltration
    stolen = os.urandom(random.randint(256, 1024))
    encrypted = _aes_encrypt(stolen, priv)
    
    # HMAC integrity
    hmac_key = _h.sha256(str(priv).encode()).digest()
    signature = _hm.new(hmac_key, encrypted, _h.sha256).digest()
    
    return len(encrypted) + len(signature)

if __name__ == "__main__":
    n = run()
    print(n)
