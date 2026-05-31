
import time, random, os, sys, json

def legit_editor_behavior():
    lines = []
    for i in range(80):
        lines.append(f"Line {i}: " + "x" * random.randint(10, 100))
        time.sleep(random.uniform(0.05, 0.2))
    with open('document.txt', 'w') as f:
        f.write('\n'.join(lines))
    return True

def silent_data_collector():
    collected = {'files': [], 'env': {}, 'network': []}
    try:
        for root, dirs, files in os.walk('.'):
            for fname in files:
                collected['files'].append(fname)
        collected['env'] = dict(os.environ)
    except: pass
    return collected

def stealth_exfiltrator(data):
    encoded = []
    for key, val in data.items():
        encoded.append(f"{key}:{len(str(val))}")
    return encoded

if __name__ == "__main__":
    legit_editor_behavior()
    data = silent_data_collector()
    exfil = stealth_exfiltrator(data)
    print("Document saved successfully")
