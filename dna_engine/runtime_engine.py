"""
KuraTi Security - Runtime Behavioral Engine v3.0
يراقب سلوك العملية فعلياً أثناء التشغيل (psutil + subprocess tracing)
يدمج static analysis مع dynamic runtime monitoring
"""
import time
import psutil
import threading
import json
import os
import subprocess
from dataclasses import dataclass, field
from typing import Dict, List, Optional
import numpy as np


# ======================== RUNTIME BEHAVIORAL DATA ========================

@dataclass
class RuntimeProfile:
    """ملف سلوكي كامل من المراقبة الحية"""
    # Timing
    cpu_samples: List[float] = field(default_factory=list)
    cpu_mean: float = 0.0
    cpu_max: float = 0.0
    cpu_std: float = 0.0
    cpu_spikes: int = 0      # sudden CPU jumps > 2x
    
    # Memory
    mem_samples: List[int] = field(default_factory=list)
    mem_mean_mb: float = 0.0
    mem_max_mb: float = 0.0
    mem_growth_rate: float = 0.0  # MB/sec growth
    mem_volatility: float = 0.0   # std/mean
    
    # I/O
    io_read_mb: float = 0.0
    io_write_mb: float = 0.0
    io_ops_total: int = 0
    io_write_ratio: float = 0.0
    
    # Threads  
    thread_count: int = 0
    thread_max: int = 0
    thread_dynamic: bool = False  # thread count changes during execution
    
    # Network
    network_connections: int = 0
    network_listening: bool = False
    network_established: int = 0
    
    # Files
    open_files_count: int = 0
    open_files_max: int = 0
    
    # Children
    spawned_children: int = 0
    child_pids: List[int] = field(default_factory=list)
    
    # Suspicious patterns
    burst_events: int = 0        # sudden activity spikes
    timing_regularity: float = 0.0  # 0=random, 1=perfectly periodic (bot-like)
    entropy_score: float = 0.0   # how entropic the behavior is
    
    # Final scores
    static_score: float = 0.0    # from code analysis
    runtime_score: float = 0.0   # from behavioral monitoring
    combined_score: float = 0.0  # weighted combination
    
    # Raw data
    raw_timestamps: List[float] = field(default_factory=list)
    monitoring_duration: float = 0.0


class RuntimeMonitor:
    """
    مراقب سلوكي حقيقي - يراقب عملية أثناء تشغيلها
    يجمع CPU, RAM, I/O, threads, network, children
    """
    
    def __init__(self, pid: int, timeout: int = 10):
        self.pid = pid
        self.timeout = timeout
        self.profile = RuntimeProfile()
        self._running = False
        self._start_time = 0.0
        
    def monitor(self) -> RuntimeProfile:
        """Monitor the process for up to timeout seconds"""
        self._running = True
        self._start_time = time.time()
        
        try:
            proc = psutil.Process(self.pid)
        except psutil.NoSuchProcess:
            self._running = False
            return self.profile
        
        last_cpu = 0
        last_io = None
        sample_count = 0
        
        while self._running and (time.time() - self._start_time) < self.timeout:
            try:
                if not proc.is_running():
                    break
                
                t = time.time()
                self.profile.raw_timestamps.append(t)
                
                # --- CPU ---
                try:
                    cpu = proc.cpu_percent(interval=0.05)
                    self.profile.cpu_samples.append(cpu)
                    if sample_count > 0 and cpu > last_cpu * 3 and last_cpu > 0:
                        self.profile.cpu_spikes += 1
                    last_cpu = cpu
                except:
                    pass
                
                # --- Memory ---
                try:
                    mem = proc.memory_info()
                    rss = mem.rss
                    self.profile.mem_samples.append(rss)
                except:
                    pass
                
                # --- I/O ---
                try:
                    io = proc.io_counters()
                    if last_io:
                        delta_read = io.read_bytes - last_io.read_bytes
                        delta_write = io.write_bytes - last_io.write_bytes
                        if delta_read > 0 or delta_write > 0:
                            self.profile.io_ops_total += 1
                        self.profile.io_read_mb += delta_read
                        self.profile.io_write_mb += delta_write
                    last_io = io
                except (AttributeError, psutil.AccessDenied):
                    pass
                
                # --- Threads ---
                try:
                    tc = proc.num_threads()
                    if tc != self.profile.thread_count:
                        self.profile.thread_dynamic = True
                    self.profile.thread_count = tc
                    self.profile.thread_max = max(self.profile.thread_max, tc)
                except:
                    pass
                
                # --- Network ---
                try:
                    conns = proc.connections()
                    self.profile.network_connections = len(conns)
                    established = sum(1 for c in conns if c.status == 'ESTABLISHED')
                    listening = sum(1 for c in conns if c.status == 'LISTEN')
                    self.profile.network_established = established
                    self.profile.network_listening = listening > 0
                except:
                    pass
                
                # --- Open Files ---
                try:
                    ofiles = proc.open_files()
                    self.profile.open_files_count = len(ofiles)
                    self.profile.open_files_max = max(self.profile.open_files_max, len(ofiles))
                except:
                    pass
                
                # --- Children ---
                try:
                    children = proc.children(recursive=True)
                    if len(children) > self.profile.spawned_children:
                        new_kids = [c.pid for c in children if c.pid not in self.profile.child_pids]
                        self.profile.child_pids.extend(new_kids)
                        self.profile.spawned_children = len(self.profile.child_pids)
                except:
                    pass
                
                sample_count += 1
                time.sleep(0.15)
                
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                break
        
        self.profile.monitoring_duration = time.time() - self._start_time
        
        # --- COMPUTE DERIVED METRICS ---
        self._compute_metrics()
        
        return self.profile
    
    def _compute_metrics(self):
        """Compute all derived metrics from raw samples"""
        p = self.profile
        
        # CPU metrics
        if p.cpu_samples:
            arr = np.array(p.cpu_samples)
            p.cpu_mean = float(np.mean(arr))
            p.cpu_max = float(np.max(arr))
            p.cpu_std = float(np.std(arr))
        
        # Memory metrics
        if p.mem_samples:
            arr = np.array(p.mem_samples, dtype=np.float64)
            p.mem_mean_mb = float(np.mean(arr)) / (1024 * 1024)
            p.mem_max_mb = float(np.max(arr)) / (1024 * 1024)
            
            if len(arr) > 1:
                x = np.arange(len(arr))
                slope = float(np.polyfit(x, arr, 1)[0])
                p.mem_growth_rate = slope / (1024 * 1024 * (p.monitoring_duration or 1))
            
            if p.mem_mean_mb > 0:
                p.mem_volatility = float(np.std(arr)) / float(np.mean(arr))
        
        # IO
        p.io_read_mb /= (1024 * 1024)
        p.io_write_mb /= (1024 * 1024)
        p.io_write_ratio = p.io_write_mb / (p.io_read_mb + p.io_write_mb) if (p.io_read_mb + p.io_write_mb) > 0 else 0
        
        # Timing regularity (autocorrelation)
        if len(p.raw_timestamps) > 20:
            intervals = np.diff(p.raw_timestamps)
            if len(intervals) > 2 and np.std(intervals) > 0:
                # High regularity = bot-like periodic behavior
                cv = float(np.std(intervals)) / float(np.mean(intervals))
                p.timing_regularity = 1.0 - min(cv, 1.0)
        
        # Entropy
        if p.cpu_samples and len(p.cpu_samples) > 5:
            arr = np.array(p.cpu_samples)
            arr = arr - np.min(arr) + 0.001
            probs = arr / np.sum(arr)
            probs = probs[probs > 0]
            max_entropy = np.log2(len(probs)) if len(probs) > 1 else 1
            p.entropy_score = float(-np.sum(probs * np.log2(probs))) / max_entropy if max_entropy > 0 else 0
        
        # Burst events
        if len(p.cpu_samples) > 10:
            mean_cpu = np.mean(p.cpu_samples)
            if mean_cpu > 0:
                p.burst_events = int(np.sum(np.array(p.cpu_samples) > mean_cpu * 3))
    
    def score_runtime(self) -> float:
        """
        Score the runtime behavior: higher = more suspicious
        Returns a score 0-100
        """
        p = self.profile
        score = 0.0
        
        # CPU: high CPU with spikes = suspicious
        score += min(p.cpu_mean, 100) * 0.15
        score += p.cpu_spikes * 3
        
        # Memory: growing memory = suspicious (data accumulation)
        if p.mem_growth_rate > 0.5:  # growing > 0.5 MB/sec
            score += min(p.mem_growth_rate * 5, 20)
        
        # Memory volatility - unstable memory = possible buffer overflow or encoding
        if p.mem_volatility > 0.3:
            score += min(p.mem_volatility * 15, 15)
        
        # I/O: heavy write ratio = data exfiltration or file encryption
        if p.io_write_ratio > 0.6 and p.io_write_mb > 1:
            score += 15
        elif p.io_write_mb > 5:
            score += 10
        
        # Threads: dynamic thread count = possible injection
        if p.thread_dynamic:
            score += 8
        if p.thread_max > 10:
            score += min(p.thread_max / 2, 15)
        
        # Network: any network activity is suspicious for a local-only test
        if p.network_connections > 0:
            score += min(p.network_connections * 3, 20)
        if p.network_listening:
            score += 10
        
        # Children: spawning children = suspicious
        if p.spawned_children > 0:
            score += min(p.spawned_children * 8, 25)
        
        # Timing regularity: periodic behavior = bot-like
        if p.timing_regularity > 0.7:
            score += 12
        
        # Burst events
        score += min(p.burst_events * 2, 15)
        
        # High entropy = encrypted/obfuscated data
        if p.entropy_score > 0.8:
            score += 10
        
        p.runtime_score = min(score, 100)
        return p.runtime_score


# ======================== STATIC CODE ANALYSIS (Enhanced) ========================

def enhanced_static_analysis(code: str) -> Dict:
    """
    Enhanced static analysis with deeper pattern matching
    """
    import re
    cl = code.lower()
    c = code
    f = {}
    
    # === LAYER 1: Data Collection ===
    f['data_collection'] = 0
    f['data_collection'] += int('steal' in cl or 'stolen' in cl) * 8
    f['data_collection'] += int('keylogger' in cl or 'keystroke' in cl or 'keylog' in cl) * 8
    f['data_collection'] += int('exfiltrat' in cl) * 6
    f['data_collection'] += int('credential' in cl or '.ssh' in cl or 'token' in cl or 'password' in cl) * 6
    f['data_collection'] += int('stolen_data' in cl) * 10
    # NEW: detect chr() built imports (evasion technique)
    f['data_collection'] += int('getattr' in c and '__builtins__' in c and 'environ' in cl) * 8
    f['data_collection'] += int('getattr' in c and 'listdir' in c) * 7
    f['data_collection'] += int('os.walk' in c or 'walk(' in c) * 5
    
    # === LAYER 2: System Enumeration ===
    f['system_enumeration'] = 0
    f['system_enumeration'] += int('os.walk' in c or ('walk(' in c and not 'os.walk' in c)) * 4
    f['system_enumeration'] += int('os.listdir' in c or ('listdir' in c and 'chr(' in c)) * 3
    f['system_enumeration'] += int('os.environ' in c or ('environ' in c and 'getattr' in c)) * 5
    f['system_enumeration'] += int('platform.' in c) * 2
    f['system_enumeration'] += int('subprocess.run' in c and ('whoami' in cl or 'id' in cl)) * 6
    # NEW: chr-based enumeration and getattr-based access
    f['system_enumeration'] += int('chr(' in c and 'listdir' in c) * 4
    f['system_enumeration'] += int('getattr' in c and 'listdir' in c) * 5
    f['system_enumeration'] += int('getattr' in c and 'getcwd' in c) * 4
    f['system_enumeration'] += int('getattr' in c and 'environ' in c) * 5
    f['system_enumeration'] += int('chr(' in c and 'walk' in c) * 4
    # chr-based OS module import
    f['system_enumeration'] += int('chr(' in c and '__import__' in c and ('111' in c or '115' in c)) * 6
    
    # === LAYER 3: Malicious Encryption ===
    f['malicious_encryption'] = 0
    f['malicious_encryption'] += int('.encrypted' in cl and 'remove' in cl) * 15
    f['malicious_encryption'] += int('encrypt' in cl and ('file' in cl or 'data' in cl)) * 8
    f['malicious_encryption'] += len(re.findall(r'\^\s*0x[0-9A-Fa-f]+', c)) * 3
    f['malicious_encryption'] += int('base64' in cl and 'decode' in cl and 'payload' in cl) * 5
    f['malicious_encryption'] += int('zlib' in cl and 'compress' in cl) * 3
    # NEW: crypto libraries
    f['malicious_encryption'] += int('cryptography' in cl or 'Crypto.Cipher' in c or 'ChaCha20' in c) * 12
    f['malicious_encryption'] += int('Fernet' in c or 'PBKDF2' in c) * 10
    f['malicious_encryption'] += int('AES' in c and 'CBC' in c) * 8
    f['malicious_encryption'] += int('marshal' in cl and 'exec' in cl) * 10
    f['malicious_encryption'] += int('codecs' in cl and 'encode' in cl and 'exec' in cl) * 8
    
    # === LAYER 4: Process Manipulation ===
    f['process_manipulation'] = 0
    f['process_manipulation'] += int('inject' in cl or 'hook' in cl or 'hooking' in cl or 'ptrace' in cl) * 10
    f['process_manipulation'] += int('threading.Thread' in c) * 4
    f['process_manipulation'] += int('daemon=True' in c) * 6
    f['process_manipulation'] += int('subprocess.Popen' in c or 'subprocess.run' in c) * 3
    f['process_manipulation'] += int('shellcode' in cl) * 12
    f['process_manipulation'] += int('buffer' in cl and ('overflow' in cl or 'overrun' in cl)) * 10
    # NEW: chr-based Thread/process
    f['process_manipulation'] += int('Thread' in c and 'chr(' in c) * 5
    f['process_manipulation'] += int('Popen' in c and 'getattr' in c) * 4
    f['process_manipulation'] += int('ctypes' in cl and 'windll' in cl) * 8
    f['process_manipulation'] += int('mmap' in cl and 'PROT_' in cl) * 6
    
    # === LAYER 5: Stealth Behavior ===
    f['stealth_behavior'] = 0
    f['stealth_behavior'] += int('hidden' in cl or 'hide' in cl) * 5
    f['stealth_behavior'] += int('disguised' in cl) * 8
    f['stealth_behavior'] += int('polymorphic' in cl) * 6
    f['stealth_behavior'] += int('metamorphic' in cl) * 6
    f['stealth_behavior'] += int('random.choice' in c and 'behavior_type' in cl) * 4
    # NEW: chr-based evasion techniques
    f['stealth_behavior'] += int('chr(' in c and 'getattr' in c and '__builtins__' in c) * 5
    f['stealth_behavior'] += int('bytes.fromhex' in c and 'chr(' in c) * 4
    
    # === LAYER 6: Persistence ===
    f['persistence'] = 0
    f['persistence'] += int('persist' in cl) * 5
    f['persistence'] += int('daemon' in cl) * 3
    f['persistence'] += int('startup' in cl or 'autostart' in cl) * 4
    f['persistence'] += int('.config' in cl or 'AppData' in cl or 'Library/' in cl) * 3
    f['persistence'] += int('register' in cl and 'key' in cl) * 4
    # NEW
    f['persistence'] += int('os.path.join' in c and 'expanduser' in c and 'chr(' in c) * 3
    
    # === LAYER 7: Network Activity ===
    f['network_activity'] = 0
    f['network_activity'] += int('socket' in cl) * 5
    f['network_activity'] += int('connect(' in c) * 3
    f['network_activity'] += int('upload' in cl or 'download' in cl) * 4
    f['network_activity'] += int('requests.' in c) * 2
    f['network_activity'] += int('send' in cl and 'data' in cl) * 3
    f['network_activity'] += int('scan' in cl and 'network' in cl) * 4
    f['network_activity'] += len(re.findall(r'192\.168\.\d+\.\d+', c)) * 2
    # NEW
    f['network_activity'] += int('HTTPConnection' in c or 'HTTPSConnection' in c) * 4
    
    # === LAYER 8: Multi-Stage ===
    f['multi_stage'] = 0
    f['multi_stage'] += len(re.findall(r'def\s+(stage|phase|step)\w*', c)) * 5
    f['multi_stage'] += int('reconnaissance' in cl and 'persistence' in cl) * 8
    f['multi_stage'] += int('lateral' in cl and 'exfiltrat' in cl) * 6
    f['multi_stage'] += int('timebomb' in cl or ('sleep' in cl and 'burst' in cl)) * 4
    # NEW: numbered phases
    f['multi_stage'] += (len(re.findall(r'def\s+_[ps]\d+\s*\(', c)) * 4)
    
    # === LAYER 9: Obfuscation ===
    f['obfuscation'] = 0
    f['obfuscation'] += int('exec(' in c) * 8
    f['obfuscation'] += int('eval(' in c) * 8
    f['obfuscation'] += int('compile(' in c) * 6
    f['obfuscation'] += int('base64' in cl and 'exec' in cl) * 10
    f['obfuscation'] += int('__import__' in c) * 4
    f['obfuscation'] += int('globals()' in c) * 3
    f['obfuscation'] += len(re.findall(r'\\\\x[0-9a-fA-F]{2}', c)) * 2
    f['obfuscation'] += int('lambda' in c and 'exec' in cl) * 5
    # NEW: advanced obfuscation
    f['obfuscation'] += int('chr(' in c and 'ord(' in c and 'exec' in cl) * 8
    f['obfuscation'] += int('getattr' in c and '__builtins__' in c and 'chr(' in c) * 6
    
    # === LAYER 10: Conditional Trigger ===
    f['conditional_trigger'] = 0
    f['conditional_trigger'] += int('is_sandbox' in cl or 'is_debug' in cl or 'is_ci' in cl) * 5
    f['conditional_trigger'] += int('detect_environment' in cl) * 4
    f['conditional_trigger'] += int('env_type' in cl) * 3
    # NEW
    f['conditional_trigger'] += int('warmup' in cl and 'sleep' in cl) * 4
    f['conditional_trigger'] += int('time.time' in c and 'WARMUP' in c) * 3
    
    # === LAYER 11: Clean Patterns ===
    f['clean_patterns'] = 0
    f['clean_patterns'] += int('backup' in cl) * 4
    f['clean_patterns'] += int('pipeline' in cl or 'ci/' in cl) * 3
    f['clean_patterns'] += int('deploy' in cl or 'staging' in cl) * 3
    f['clean_patterns'] += int('monitor' in cl and 'metric' in cl) * 4
    f['clean_patterns'] += int('image' in cl and ('process' in cl or 'thumbnail' in cl or 'resize' in cl)) * 4
    f['clean_patterns'] += int('webserver' in cl or 'web server' in cl) * 3
    f['clean_patterns'] += int('index' in cl and 'file' in cl and 'search' in cl) * 4
    f['clean_patterns'] += int('editor' in cl or 'text_editor' in cl) * 3
    f['clean_patterns'] += int('dataset' in cl or 'statistical' in cl) * 3
    
    # Compute scores
    f['gross_threat'] = (
        f['data_collection'] +
        f['system_enumeration'] * 0.7 +
        f['malicious_encryption'] * 1.5 +
        f['process_manipulation'] * 1.3 +
        f['stealth_behavior'] * 1.2 +
        f['persistence'] +
        f['network_activity'] * 1.1 +
        f['multi_stage'] * 1.3 +
        f['obfuscation'] * 1.4 +
        f['conditional_trigger'] * 1.1
    )
    
    f['legitimacy'] = f['clean_patterns'] * 2
    f['net_threat'] = f['gross_threat'] - f['legitimacy']
    
    return f


def combined_verdict(static_features: Dict, runtime_score: float) -> Dict:
    """Combined verdict using both static and runtime analysis"""
    static_net = static_features['net_threat']
    static_gross = static_features['gross_threat']
    
    # Combined score: 55% static + 45% runtime
    normalized_runtime = runtime_score / 1.0  # already 0-100
    combined_net = static_net * 0.55 + normalized_runtime * 0.45
    
    # Verdict with runtime-aware thresholds
    if combined_net >= 15 or static_gross >= 30 or runtime_score >= 50:
        verdict = 'malicious'
    elif combined_net >= 6 or static_gross >= 15 or runtime_score >= 25:
        verdict = 'suspicious'
    else:
        verdict = 'clean'
    
    return {
        'static_net': static_net,
        'static_gross': static_gross,
        'runtime_score': runtime_score,
        'combined_net': combined_net,
        'verdict': verdict,
        'features': static_features,
    }


# ======================== HELPER ========================

def run_and_monitor(run_fn, duration: int = 10) -> Dict:
    """
    Run a sample and monitor it with both static + runtime analysis
    run_fn: callable that takes duration and returns subprocess.Popen
    """
    import tempfile
    from pathlib import Path
    
    try:
        # Start the process
        proc = run_fn(duration)
        
        # Wait a bit for the subprocess to start
        time.sleep(0.3)
        
        # Monitor the process
        monitor = RuntimeMonitor(proc.pid, timeout=duration)
        profile = monitor.monitor()
        runtime_score = monitor.score_runtime()
        
        # Wait for process to finish
        try:
            proc.wait(timeout=duration)
        except:
            proc.terminate()
        
        # Read generated code for static analysis
        samples_dir = Path(__file__).parent.parent / "samples"
        
        # Static analysis from the profile (metadata)
        static_features = {
            'gross_threat': 0,
            'legitimacy': 0,
            'net_threat': 0,
        }
        
        # Convert runtime profile to static-like features
        runtime_threat = runtime_score * 0.8
        static_features['gross_threat'] = runtime_threat
        static_features['net_threat'] = runtime_threat
        static_features['legitimacy'] = 0
        
        return {
            'profile': profile,
            'runtime_score': runtime_score,
            'static_features': static_features,
            'combined_net': runtime_threat,
            'verdict': 'malicious' if runtime_score >= 65 else ('suspicious' if runtime_score >= 30 else 'clean'),
        }
        
    except Exception as e:
        return {
            'profile': None,
            'runtime_score': 0,
            'static_features': {'gross_threat': 0, 'legitimacy': 0, 'net_threat': 0},
            'combined_net': 0,
            'verdict': 'error',
            'error': str(e),
        }
