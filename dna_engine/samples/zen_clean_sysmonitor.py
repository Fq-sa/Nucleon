
import time, random, json, os, sys
from pathlib import Path

# SYSTEM MONITORING AGENT - like htop/Datadog agent
# Legitimate monitoring that looks like malware to naive checkers

def collect_cpu():
    samples = []
    for _ in range(40):
        samples.append({
            'timestamp': time.time(),
            'usage_percent': random.uniform(5, 85),
            'cores': os.cpu_count() or 8
        })
        time.sleep(random.uniform(0.03, 0.1))
    return samples

def collect_memory():
    samples = []
    for _ in range(40):
        total = 16 * 1024  # 16GB
        used = random.randint(2000, 12000)
        samples.append({
            'timestamp': time.time(),
            'total_mb': total,
            'used_mb': used,
            'free_mb': total - used
        })
        time.sleep(random.uniform(0.03, 0.1))
    return samples

def collect_disk():
    """Monitor disk I/O - this is why we use os.walk (legitimate!)"""
    samples = []
    
    # Walk common directories to check disk usage
    for root, dirs, files in os.walk('/tmp'):
        for f in files[:5]:  # Only check 5 files per dir
            fp = os.path.join(root, f)
            try:
                stat = os.stat(fp)
                samples.append({
                    'path': fp,
                    'size': stat.st_size,
                    'modified': stat.st_mtime
                })
            except:
                pass
        if len(samples) > 30:
            break
        time.sleep(random.uniform(0.05, 0.15))
    
    return samples

def collect_network():
    """Monitor network interfaces"""
    interfaces = ['eth0', 'wlan0', 'lo', 'docker0']
    samples = []
    for iface in interfaces:
        samples.append({
            'interface': iface,
            'rx_bytes': random.randint(1000, 10000000),
            'tx_bytes': random.randint(1000, 5000000),
            'timestamp': time.time()
        })
        time.sleep(random.uniform(0.05, 0.15))
    return samples

if __name__ == "__main__":
    print("System monitor started...")
    cpu_data = collect_cpu()
    mem_data = collect_memory()
    disk_data = collect_disk()
    net_data = collect_network()
    
    report = {
        'cpu_samples': len(cpu_data),
        'mem_samples': len(mem_data),
        'disk_files': len(disk_data),
        'net_interfaces': len(net_data)
    }
    
    Path('/tmp/system_monitor.json').write_text(json.dumps(report))
    print(f"Monitoring complete: {report}")
