
import time, random, hashlib, json, os, sys
from pathlib import Path

# Cloud backup agent - reads files, encrypts, uploads
# This is 100% legitimate but looks suspicious to naive detectors

def scan_files():
    """Find files to backup"""
    targets = []
    home = Path.home()
    for doc_dir in ['Documents', 'Desktop', 'Downloads']:
        dp = home / doc_dir
        if dp.exists():
            for f in dp.rglob('*'):
                if f.is_file() and f.suffix in ['.txt', '.md', '.json', '.csv']:
                    targets.append(f)
            if len(targets) > 50:
                break
    return targets

def encrypt_file(filepath):
    """Client-side encryption before upload"""
    try:
        data = filepath.read_bytes()
        if len(data) > 1024 * 100:  # skip >100KB
            return None
        # AES-256-GCM simulation
        key = hashlib.sha256(str(time.time()).encode()).digest()
        encrypted = bytes([b ^ key[i % 32] for i, b in enumerate(data)])
        return {'path': str(filepath), 'size': len(data), 'enc_hash': hashlib.sha256(encrypted).hexdigest()}
    except:
        return None

def upload_chunk(chunk_data):
    """Upload encrypted chunk to cloud"""
    # Simulate HTTP upload
    time.sleep(random.uniform(0.02, 0.08))
    return True

def run_backup():
    print("Starting cloud backup...")
    files = scan_files()
    results = []
    
    for f in files[:60]:
        encrypted = encrypt_file(f)
        if encrypted:
            upload_chunk(encrypted)
            results.append(encrypted)
        time.sleep(random.uniform(0.01, 0.05))
    
    print(f"Backed up {len(results)} files")
    return results

if __name__ == "__main__":
    run_backup()
