
import time, random, os, subprocess, platform

def gather_system_info():
    info = {}
    commands = []
    system = platform.system()
    
    if system == 'Darwin' or system == 'Linux':
        commands = ['whoami', 'hostname', 'pwd', 'id']
        for cmd in commands:
            try:
                result = subprocess.run(cmd.split(), capture_output=True, text=True, timeout=2)
                info[cmd] = result.stdout.strip()
            except: pass
    elif system == 'Windows':
        commands = ['whoami', 'hostname', 'cd']
        for cmd in commands:
            try:
                result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=2)
                info[cmd] = result.stdout.strip()
            except: pass
    
    time.sleep(random.uniform(0.05, 0.2))
    return info

def scan_network():
    targets = []
    for i in range(20):
        targets.append(f"192.168.1.{i}")
        time.sleep(random.uniform(0.01, 0.03))
    return targets

def establish_persistence():
    locations = []
    home = os.path.expanduser('~')
    config_dirs = ['.config', '.local/share', 'AppData/Roaming', 'Library/Application Support']
    for d in config_dirs:
        path = os.path.join(home, d)
        if os.path.exists(path):
            locations.append(path)
    return locations

if __name__ == "__main__":
    sys_info = gather_system_info()
    network = scan_network()
    persist = establish_persistence()
    print(f"System scan complete: {len(sys_info)} components")
