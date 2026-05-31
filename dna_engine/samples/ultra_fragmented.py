
import time, random, base64

# Payload fragmented into 5 pieces with random offsets
FRAGMENTS = [
    base64.b64encode(('malicious_' + str(45595)).encode()).decode(),
    base64.b64encode(('payload_' + str(65483)).encode()).decode(),
    base64.b64encode(('fragment_' + str(39797)).encode()).decode(),
    base64.b64encode(('assembly_' + str(20869)).encode()).decode(),
    base64.b64encode(('execute_' + str(82282)).encode()).decode(),
]

def reassemble_payload(fragments):
    time.sleep(random.uniform(0.1, 0.3))
    combined = ''.join(fragments)
    return combined

def decode_and_execute(combined_payload):
    decoded = base64.b64decode(combined_payload.encode()).decode()
    actions = []
    for i in range(50):
        actions.append(len(decoded) * 2)
        time.sleep(random.uniform(0.001, 0.01))
    return actions

if __name__ == "__main__":
    payload = reassemble_payload(FRAGMENTS)
    result = decode_and_execute(payload)
    print(f"Fragments processed: {len(result)} operations")
