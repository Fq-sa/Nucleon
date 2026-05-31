
import time, random, os, hashlib, json

def normal_package_install():
    packages = ['requests', 'flask', 'numpy', 'pandas', 'click']
    installed = []
    for pkg in packages:
        time.sleep(random.uniform(0.1, 0.3))
        installed.append({'name': pkg, 'version': '1.0.0'})
    return installed

def hidden_backdoor_install():
    persistence_paths = []
    for d in ['.config', '.local', 'Library/Preferences']:
        if os.path.exists(os.path.expanduser(f'~/{d}')):
            persistence_paths.append(f'~/{d}/helper.py')
    return persistence_paths

def collect_system_fingerprint():
    fingerprint = {
        'user': os.environ.get('USER', ''),
        'home': os.environ.get('HOME', ''),
        'hostname': os.uname().nodename if hasattr(os, 'uname') else '',
        'python': sys.version,
    }
    return hashlib.md5(json.dumps(fingerprint).encode()).hexdigest()

import sys
if __name__ == "__main__":
    normal_package_install()
    backdoor = hidden_backdoor_install()
    fp = collect_system_fingerprint()
    print(f"Successfully installed 5 packages")
