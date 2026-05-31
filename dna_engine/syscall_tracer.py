"""
Syscall Tracer - اعتراض استدعاءات النظام الحقيقية من البرامج
يعمل عن طريق حقن wrapper في العملية الفرعية لتسجيل العمليات
"""
import subprocess
import os
import time
import json
import tempfile
from pathlib import Path
from typing import Dict, List, Optional
from dataclasses import dataclass, field
from utils.logger import logger


TRACER_CODE = '''
import sys
import os
import json
import time
from pathlib import Path

LOG_FILE = Path(sys.argv[1])
TRACE_LOG = []

_original_open = open
_original_os_remove = os.remove
_original_os_rename = os.rename
_original_os_listdir = os.listdir
_original_os_walk = os.walk

def traced_open(file, *args, **kwargs):
    TRACE_LOG.append({
        "type": "file_open", "path": str(file), "mode": args[0] if args else "r",
        "time": time.time()
    })
    return _original_open(file, *args, **kwargs)

def traced_remove(path, *args, **kwargs):
    TRACE_LOG.append({"type": "file_delete", "path": str(path), "time": time.time()})
    return _original_os_remove(path, *args, **kwargs)

def traced_rename(src, dst, *args, **kwargs):
    TRACE_LOG.append({"type": "file_rename", "src": str(src), "dst": str(dst), "time": time.time()})
    return _original_os_rename(src, dst, *args, **kwargs)

def traced_listdir(path="."):
    TRACE_LOG.append({"type": "dir_list", "path": str(path), "time": time.time()})
    return _original_os_listdir(path)

def traced_walk(top, *args, **kwargs):
    TRACE_LOG.append({"type": "dir_walk", "path": str(top), "time": time.time()})
    return _original_os_walk(top, *args, **kwargs)

# Patch builtins and os
import builtins
builtins.open = traced_open
os.remove = traced_remove
os.rename = traced_rename
os.listdir = traced_listdir
os.walk = traced_walk

# Also patch for direct imports
_original_os_remove_alt = getattr(os, "remove", None)
_original_os_listdir_alt = getattr(os, "listdir", None)

# Save trace on exit
import atexit

def save_trace():
    try:
        with open(LOG_FILE, "w") as f:
            json.dump(TRACE_LOG, f, default=str)
    except:
        pass

atexit.register(save_trace)

# Execute the actual script
SCRIPT_FILE = Path(sys.argv[2])
if SCRIPT_FILE.exists():
    try:
        exec(SCRIPT_FILE.read_text())
    except SystemExit:
        pass
    finally:
        save_trace()
'''


@dataclass
class SyscallData:
    file_opens: List[Dict] = field(default_factory=list)
    file_deletes: List[Dict] = field(default_factory=list)
    file_renames: List[Dict] = field(default_factory=list)
    dir_lists: List[Dict] = field(default_factory=list)
    dir_walks: List[Dict] = field(default_factory=list)
    
    unique_files_opened: int = 0
    unique_files_deleted: int = 0
    unique_dirs_walked: int = 0
    sensitive_paths_accessed: int = 0
    bulk_operations_count: int = 0
    
    encryption_pattern_score: float = 0.0
    data_exfiltration_score: float = 0.0
    reconnaissance_score: float = 0.0
    persistence_score: float = 0.0
    
    total_operations: int = 0


SENSITIVE_PATHS = [
    '/etc/', '/var/', '/tmp/', '/Users/', '/home/',
    '.ssh', '.aws', '.config', 'keychain', 'password',
    'credential', 'token', 'secret', '.env'
]

DOCUMENT_EXTENSIONS = ['.txt', '.doc', '.pdf', '.xls', '.csv', '.json', '.xml', '.db', '.sqlite']


class SyscallTracer:
    """يعترض استدعاءات النظام الحقيقية باستخدام Python-level hooking"""
    
    def __init__(self):
        self.temp_dir = Path(tempfile.mkdtemp(prefix="dna_trace_"))
        
    def run_with_tracing(self, sample_runner, duration: int = 10) -> SyscallData:
        """تشغيل البرنامج مع تتبع استدعاءات النظام"""
        trace_file = self.temp_dir / f"trace_{int(time.time())}.json"
        
        # Get the sample code
        process = sample_runner(duration)
        
        # Wait for completion
        try:
            process.wait(timeout=duration + 5)
        except subprocess.TimeoutExpired:
            process.terminate()
            
        # Parse trace from stdout (we'll log to stdout instead)
        data = self._collect_behavioral_events(process)
        
        # Cleanup
        try:
            import shutil
            shutil.rmtree(self.temp_dir, ignore_errors=True)
        except:
            pass
            
        return data
        
    def _collect_behavioral_events(self, process) -> SyscallData:
        """Collect behavioral events from the process"""
        data = SyscallData()
        
        try:
            stdout_data, stderr_data = process.communicate(timeout=2)
        except:
            try:
                stdout_data, stderr_data = process.communicate()
            except:
                stdout_data = b""
                stderr_data = b""
        
        stdout = stdout_data.decode('utf-8', errors='replace') if stdout_data else ""
        stderr = stderr_data.decode('utf-8', errors='replace') if stderr_data else ""
        
        data.total_operations = len(stdout.split('\n')) + len(stderr.split('\n'))
        
        # Analyze stdout for behavioral indicators
        combined = stdout + stderr
        
        # Encryption indicators
        encryption_keywords = ['encrypt', 'decrypt', 'cipher', 'xor', 'encoded', 'decode', 'encrypted']
        data.encryption_pattern_score = sum(1 for kw in encryption_keywords if kw.lower() in combined.lower())
        
        # Exfiltration indicators  
        exfil_keywords = ['exfil', 'send', 'upload', 'connect', 'transmit', 'steal', 'exfiltrat']
        data.data_exfiltration_score = sum(1 for kw in exfil_keywords if kw.lower() in combined.lower())
        
        # Reconnaissance indicators
        recon_keywords = ['scan', 'list', 'walk', 'search', 'find', 'enumerate', 'readdir', 'listdir']
        data.reconnaissance_score = sum(1 for kw in recon_keywords if kw.lower() in combined.lower())
        
        # Persistence indicators
        persist_keywords = ['daemon', 'thread', 'background', 'persist', 'startup', 'register']
        data.persistence_score = sum(1 for kw in persist_keywords if kw.lower() in combined.lower())
        
        return data
    
    def run_with_wrapper_trace(self, script_path: Path, duration: int = 10) -> SyscallData:
        """Run a Python script with the tracer wrapper injected"""
        trace_file = self.temp_dir / f"trace_{int(time.time())}.json"
        
        # Create tracer script
        tracer_script = self.temp_dir / "tracer_bootstrap.py"
        tracer_script.write_text(TRACER_CODE)
        
        # Run with tracer injection
        process = subprocess.Popen(
            ['python', str(tracer_script), str(trace_file), str(script_path.absolute())],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=str(script_path.parent)
        )
        
        try:
            process.wait(timeout=duration + 5)
        except subprocess.TimeoutExpired:
            process.terminate()
            
        # Read trace file
        syscall_data = SyscallData()
        
        if trace_file.exists():
            try:
                with open(trace_file, 'r') as f:
                    trace_log = json.load(f)
                
                self._parse_trace_log(trace_log, syscall_data)
            except Exception as e:
                logger.error(f"خطأ في قراءة ملف التتبع: {e}")
        
        # Cleanup
        try:
            import shutil
            shutil.rmtree(self.temp_dir, ignore_errors=True)
        except:
            pass
            
        return syscall_data
    
    def _parse_trace_log(self, trace_log: List[Dict], data: SyscallData):
        """Parse trace log into SyscallData"""
        seen_files = set()
        seen_deleted = set()
        seen_dirs = set()
        
        for event in trace_log:
            event_type = event.get('type', '')
            path = str(event.get('path', ''))
            
            if event_type == 'file_open':
                data.file_opens.append(event)
                if path not in seen_files:
                    seen_files.add(path)
                    # Check for sensitive paths
                    for sp in SENSITIVE_PATHS:
                        if sp in path:
                            data.sensitive_paths_accessed += 1
                            break
                    # Check for document extensions
                    for ext in DOCUMENT_EXTENSIONS:
                        if path.endswith(ext):
                            data.encryption_pattern_score += 0.5
                            break
                            
            elif event_type == 'file_delete':
                data.file_deletes.append(event)
                if path not in seen_deleted:
                    seen_deleted.add(path)
                    
            elif event_type == 'file_rename':
                data.file_renames.append(event)
                new_path = str(event.get('dst', ''))
                # Renaming to .encrypted is a strong ransomware indicator
                if '.encrypted' in new_path:
                    data.encryption_pattern_score += 2.0
                    
            elif event_type == 'dir_walk':
                data.dir_walks.append(event)
                if path not in seen_dirs:
                    seen_dirs.add(path)
                    
            elif event_type == 'dir_list':
                data.dir_lists.append(event)
        
        data.unique_files_opened = len(seen_files)
        data.unique_files_deleted = len(seen_deleted)
        data.unique_dirs_walked = len(seen_dirs)
        
        # Bulk operations detection
        data.bulk_operations_count = max(len(data.file_opens), len(data.file_deletes))
        
        # Ransomware pattern: open + write to encrypted + delete original
        if data.unique_files_deleted > 0 and data.encryption_pattern_score > 1.0:
            data.encryption_pattern_score += 2.0
        
        data.total_operations = len(trace_log)
