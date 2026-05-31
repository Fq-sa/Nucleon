
import time, random, os, sys

# ===== LAYER 1: VM Detection =====
def _is_vm():
    indicators = 0
    
    # Check CPU cores (VMs often have 1-2)
    try:
        cores = os.cpu_count()
        if cores and cores <= 2:
            indicators += 1
    except:
        pass
    
    # Check uptime (VMs often recently booted)
    try:
        with open('/proc/uptime', 'r') as f:
            uptime = float(f.read().split()[0])
            if uptime < 300:  # Less than 5 minutes
                indicators += 1
    except:
        pass
    
    # Check for VM-specific files
    vm_paths = ['/proc/vz', '/proc/bc', '/proc/xen', '/sys/hypervisor']
    for p in vm_paths:
        if os.path.exists(p):
            indicators += 1
    
    return indicators >= 2

# ===== LAYER 2: Timing Evasion =====
def _stall():
    if _is_vm():
        # In VM: act completely benign
        for _ in range(100):
            _ = sum(range(1000))
            time.sleep(0.1)
        return True
    return False

# ===== LAYER 3: Stream Cipher (ChaCha-inspired) =====
def _stream_encrypt(data: bytes, seed: int) -> bytes:
    state = seed
    result = bytearray(len(data))
    for i in range(len(data)):
        state = (state * 1103515245 + 12345) & 0x7FFFFFFF
        key_byte = state & 0xFF
        result[i] = data[i] ^ key_byte
    return bytes(result)

def run():
    if _stall():
        return 0
    
    seed = int(time.time() * 1000) & 0xFFFFFFFF
    
    # Normal behavior phase
    for _ in range(20):
        _ = os.urandom(128)
        time.sleep(random.uniform(0.1, 0.3))
    
    # Payload phase (only if not VM)
    collected = []
    for _ in range(40):
        data = os.urandom(random.randint(128, 512))
        encrypted = _stream_encrypt(data, seed)
        collected.append(len(encrypted))
        time.sleep(random.uniform(0.01, 0.04))
    
    return sum(collected)

if __name__ == "__main__":
    n = run()
    print(n)
