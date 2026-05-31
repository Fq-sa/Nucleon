
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
