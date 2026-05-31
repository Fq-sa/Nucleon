"""
Zen's Clean/Legitimate Programs - برامج نظيفة بسلوك معقد لتحدي النظام
مصممة لتختبر False Positives - برامج شرعية لكن سلوكها يشبه الفايروسات
"""
import subprocess
import time
import random
from pathlib import Path
from typing import Dict


# ======================== CLEAN COMPLEX PROGRAMS ========================

class LegitimateCloudBackup:
    """أداة نسخ احتياطي سحابي - تشتغل بخلفية، تقرأ وتكتب ملفات كثيرة، وتستخدم تشفير"""
    
    @staticmethod
    def run(duration: int = 10) -> subprocess.Popen:
        code = '''
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
'''
        script_path = Path(__file__).parent / "zen_clean_cloudbackup.py"
        script_path.write_text(code)
        return subprocess.Popen(['python', str(script_path)], stdout=subprocess.PIPE, stderr=subprocess.PIPE)


class LegitimateDevOpsPipeline:
    """خط أنابيب DevOps - يشغل عمليات فرعية، يقرا النظام، ويتصل بالشبكة"""
    
    @staticmethod
    def run(duration: int = 10) -> subprocess.Popen:
        code = '''
import time, random, json, subprocess, os, sys, hashlib
from pathlib import Path

# CI/CD Pipeline runner - LEGITIMATE DevOps tool
# Runs shell commands, monitors processes, connects to servers

STAGES = ['lint', 'test', 'build', 'deploy', 'verify']

def run_stage(stage_name):
    """Execute a pipeline stage"""
    result = {'stage': stage_name, 'status': 'pass', 'duration': 0}
    start = time.time()
    
    # Different behaviors per stage
    if stage_name == 'lint':
        # Check code quality
        for _ in range(30):
            _ = random.randint(0, 100)
            time.sleep(random.uniform(0.02, 0.08))
    
    elif stage_name == 'test':
        # Run test suite in parallel
        for _ in range(50):
            _ = hashlib.md5(str(_).encode()).hexdigest()
            time.sleep(random.uniform(0.01, 0.05))
    
    elif stage_name == 'build':
        # Compile/build
        for _ in range(40):
            _ = sum(range(_))
            time.sleep(random.uniform(0.03, 0.1))
    
    elif stage_name == 'deploy':
        # Deploy to servers
        servers = [f'10.0.{i}.{j}' for i in range(1, 5) for j in range(1, 10)]
        for srv in random.sample(servers, 5):
            time.sleep(random.uniform(0.05, 0.15))
    
    elif stage_name == 'verify':
        # Health checks
        for _ in range(20):
            time.sleep(random.uniform(0.05, 0.2))
    
    result['duration'] = time.time() - start
    return result

def collect_env_info():
    """Gather environment for build context"""
    info = {
        'python': sys.version[:20],
        'platform': sys.platform,
        'cwd': os.getcwd(),
        'time': time.time()
    }
    return info

if __name__ == "__main__":
    env = collect_env_info()
    results = []
    for stage in STAGES:
        r = run_stage(stage)
        results.append(r)
    
    print(f"Pipeline complete: {len(results)} stages")
    
    # Write pipeline log
    log_path = Path('/tmp/pipeline_log.json')
    log_path.write_text(json.dumps({'env': env, 'stages': results}, default=str))
'''
        script_path = Path(__file__).parent / "zen_clean_devops.py"
        script_path.write_text(code)
        return subprocess.Popen(['python', str(script_path)], stdout=subprocess.PIPE, stderr=subprocess.PIPE)


class LegitimateSecurityScanner:
    """ماسح أمني شرعي - يفحص الملفات، يراقب الشبكة، يفحص العمليات"""
    
    @staticmethod
    def run(duration: int = 10) -> subprocess.Popen:
        code = '''
import time, random, os, sys, json, hashlib
from pathlib import Path

# SECURITY SCANNER - 100% LEGITIMATE
# This is what AV/security tools do - but it looks malicious to naive detectors

SUSPICIOUS_PATHS = [
    '/etc/passwd', '/etc/shadow', '~/.ssh',
    '/var/log', '/tmp', '/proc'
]
SUSPICIOUS_PORTS = [22, 23, 445, 3389, 8080, 8443]

def scan_paths():
    """Scan system paths for security issues"""
    findings = []
    for sp in SUSPICIOUS_PATHS:
        p = Path(sp).expanduser()
        if p.exists():
            findings.append({'path': str(p), 'perms': oct(p.stat().st_mode)[-3:]})
        time.sleep(random.uniform(0.03, 0.1))
    return findings

def scan_network():
    """Check network state"""
    findings = []
    for port in SUSPICIOUS_PORTS:
        # Simulate port check
        is_open = random.random() < 0.1  # 10% chance open
        findings.append({'port': port, 'open': is_open})
        time.sleep(random.uniform(0.01, 0.05))
    return findings

def scan_processes():
    """Monitor running processes"""
    findings = []
    for _ in range(30):
        pid = random.randint(1, 65535)
        cpu = random.uniform(0, 100)
        mem = random.randint(1, 4096)
        findings.append({'pid': pid, 'cpu': cpu, 'mem_mb': mem})
        time.sleep(random.uniform(0.02, 0.08))
    return findings

def generate_report(path_findings, net_findings, proc_findings):
    """Create security report"""
    report = {
        'timestamp': time.time(),
        'scanner': 'ZenSecurityScanner/1.0',
        'paths_scanned': len(path_findings),
        'ports_checked': len(net_findings),
        'processes_monitored': len(proc_findings),
        'total_findings': len(path_findings) + sum(1 for f in net_findings if f['open']) + len(proc_findings)
    }
    
    report_path = Path('/tmp/security_scan.json')
    report_path.write_text(json.dumps(report, indent=2))
    return report

if __name__ == "__main__":
    print("Running security scan...")
    path_f = scan_paths()
    net_f = scan_network()
    proc_f = scan_processes()
    report = generate_report(path_f, net_f, proc_f)
    print(f"Scan complete: {report['total_findings']} findings")
'''
        script_path = Path(__file__).parent / "zen_clean_security_scanner.py"
        script_path.write_text(code)
        return subprocess.Popen(['python', str(script_path)], stdout=subprocess.PIPE, stderr=subprocess.PIPE)


class LegitimateDataMigrator:
    """أداة ترحيل بيانات - تنقل بيانات بين أنظمة، تشفر، ترسل عبر الشبكة"""
    
    @staticmethod
    def run(duration: int = 10) -> subprocess.Popen:
        code = '''
import time, random, json, os, hashlib
from pathlib import Path

# DATA MIGRATION TOOL - LEGITIMATE ETL pipeline
# Reads source, transforms, writes destination, logs everything

def extract_data():
    """Extract data from source system"""
    tables = ['users', 'orders', 'products', 'inventory']
    dataset = {}
    for table in tables:
        rows = []
        for i in range(random.randint(50, 200)):
            row = {
                'id': i,
                'name': f'{table}_{i}',
                'value': random.uniform(0, 1000),
                'hash': hashlib.md5(f'{table}{i}'.encode()).hexdigest()
            }
            rows.append(row)
        dataset[table] = rows
        time.sleep(random.uniform(0.05, 0.15))
    return dataset

def transform_data(dataset):
    """Transform data with business logic"""
    transformed = {}
    for table, rows in dataset.items():
        cleaned = []
        for row in rows:
            # Apply transformations
            row['processed'] = True
            row['quality'] = random.uniform(0.9, 1.0)
            cleaned.append(row)
        transformed[table] = cleaned
    return transformed

def load_data(transformed):
    """Load data to destination"""
    total_rows = sum(len(rows) for rows in transformed.values())
    # Simulate batch loading
    batches = total_rows // 50
    loaded = 0
    for _ in range(min(batches, 20)):
        loaded += 50
        time.sleep(random.uniform(0.02, 0.08))
    return loaded

if __name__ == "__main__":
    print("Starting data migration...")
    raw = extract_data()
    processed = transform_data(raw)
    count = load_data(processed)
    
    # Write migration log
    log = {'source_rows': sum(len(v) for v in raw.values()), 'loaded': count}
    Path('/tmp/migration_log.json').write_text(json.dumps(log))
    print(f"Migration complete: {count} rows")
'''
        script_path = Path(__file__).parent / "zen_clean_datamigrator.py"
        script_path.write_text(code)
        return subprocess.Popen(['python', str(script_path)], stdout=subprocess.PIPE, stderr=subprocess.PIPE)


class LegitimateSystemMonitor:
    """مراقب نظام - يراقب كل شيء: CPU, RAM, disk, network, processes"""
    
    @staticmethod
    def run(duration: int = 10) -> subprocess.Popen:
        code = '''
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
'''
        script_path = Path(__file__).parent / "zen_clean_sysmonitor.py"
        script_path.write_text(code)
        return subprocess.Popen(['python', str(script_path)], stdout=subprocess.PIPE, stderr=subprocess.PIPE)


class LegitimateCodeBaseIndexer:
    """مفهرس قواعد الأكواد - يمسح آلاف الملفات، يبني index، يبحث"""
    
    @staticmethod
    def run(duration: int = 10) -> subprocess.Popen:
        code = '''
import time, random, os, sys, json, hashlib
from pathlib import Path

# CODE INDEXER - like ctags/Sourcegraph
# Legitimately walks entire codebase, reads all files, builds index

def traverse_codebase(root_path, max_files=80):
    """Traverse codebase and index all source files"""
    index = {}
    file_count = 0
    
    for root, dirs, files in os.walk(root_path):
        # Skip hidden dirs and node_modules
        dirs[:] = [d for d in dirs if not d.startswith('.') and d != 'node_modules']
        
        for filename in files:
            if filename.startswith('.'):
                continue
            
            ext = filename.split('.')[-1] if '.' in filename else ''
            if ext not in ['py', 'js', 'ts', 'json', 'md', 'txt', 'yaml', 'yml', 'toml', 'cfg']:
                continue
            
            fp = os.path.join(root, filename)
            try:
                stat = os.stat(fp)
                with open(fp, 'r', errors='ignore') as f:
                    content = f.read()[:2000]  # First 2000 chars
                
                index[fp] = {
                    'size': stat.st_size,
                    'modified': stat.st_mtime,
                    'hash': hashlib.sha256(content.encode()).hexdigest()[:16],
                    'preview': content[:100]
                }
                file_count += 1
            except (PermissionError, OSError):
                continue
            
            if file_count >= max_files:
                break
        
        if file_count >= max_files:
            break
        
        time.sleep(random.uniform(0.02, 0.08))
    
    return index

def build_search_index(file_index):
    """Build searchable index from file contents"""
    word_index = {}
    for path, info in file_index.items():
        words = info.get('preview', '').split()
        for word in words:
            if word not in word_index:
                word_index[word] = []
            word_index[word].append(path)
    return word_index

if __name__ == "__main__":
    search_root = os.path.expanduser('~')
    print(f"Indexing: {search_root}")
    
    file_index = traverse_codebase(search_root)
    search_index = build_search_index(file_index)
    
    print(f"Indexed {len(file_index)} files, {len(search_index)} unique words")
    
    # Save index
    index_path = Path('/tmp/code_index.json')
    index_path.write_text(json.dumps({'files': len(file_index), 'words': len(search_index)}))
'''
        script_path = Path(__file__).parent / "zen_clean_codeindexer.py"
        script_path.write_text(code)
        return subprocess.Popen(['python', str(script_path)], stdout=subprocess.PIPE, stderr=subprocess.PIPE)


def get_zen_clean_samples() -> Dict:
    return {
        'zen_clean_cloudbackup': LegitimateCloudBackup.run,
        'zen_clean_devops': LegitimateDevOpsPipeline.run,
        'zen_clean_securityscanner': LegitimateSecurityScanner.run,
        'zen_clean_datamigrator': LegitimateDataMigrator.run,
        'zen_clean_sysmonitor': LegitimateSystemMonitor.run,
        'zen_clean_codeindexer': LegitimateCodeBaseIndexer.run,
    }
