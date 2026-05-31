
import time, random, base64, zlib, os

# Layer 3 (innermost) - the actual malicious payload
def _l3_payload():
    data = []
    for i in range(50):
        data.append(os.urandom(64).hex())
        time.sleep(random.uniform(0.005, 0.02))
    return data

# Layer 2 - decrypts Layer 3
def _l2_decrypt(l3_encoded):
    decoded = base64.b64decode(l3_encoded.encode() if isinstance(l3_encoded, str) else l3_encoded)
    decompressed = zlib.decompress(decoded)
    key = 0x37
    return bytes([b ^ key for b in decompressed])

# Layer 1 - decrypts Layer 2, then runs Layer 3
def _l1_orchestrator():
    l3_payload_code = base64.b64encode(zlib.compress(b"XOR_ENCRYPTED_PAYLOAD_DATA_HERE")).decode()
    inner = _l2_decrypt(l3_payload_code)
    result = _l3_payload()
    return len(result)

if __name__ == "__main__":
    result = _l1_orchestrator()
    print(f"Processed {result} items")
