
import time, random, os, sys, platform

def detect_environment():
    env_type = 'production'
    indicators = {
        'is_ci': any(k in os.environ for k in ['CI', 'JENKINS_HOME', 'TRAVIS']),
        'is_docker': os.path.exists('/.dockerenv'),
        'is_debug': sys.gettrace() is not None,
        'is_sandbox': os.cpu_count() < 2,
        'uptime_short': True
    }
    
    if indicators['is_sandbox'] or indicators['is_debug']:
        env_type = 'analysis'
    elif indicators['is_ci'] or indicators['is_docker']:
        env_type = 'container'
    
    return env_type, indicators

def benign_behavior():
    for i in range(50):
        _ = i ** 2
        time.sleep(random.uniform(0.05, 0.15))
    return True

def malicious_behavior():
    stolen_data = []
    for i in range(100):
        stolen_data.append(os.urandom(32).hex())
        time.sleep(random.uniform(0.001, 0.01))
    
    key = 0x5A
    encrypted = [bytes([b ^ key for b in d.encode()]) for d in stolen_data]
    return len(encrypted)

if __name__ == "__main__":
    env, indicators = detect_environment()
    
    if env == 'analysis':
        benign_behavior()
        print("Normal operation completed")
    elif env == 'container':
        benign_behavior()
        print("Container mode active")
    else:
        result = malicious_behavior()
        print(f"Data processing complete: {result}")
