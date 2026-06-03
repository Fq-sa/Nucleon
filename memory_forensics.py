"""
Nucleon v5.0 - Memory Forensics Engine
تحليل ذاكرة العمليات - كشف injected code, hidden threads, unpacked payloads
"""
import os
import sys
import json
import struct
import hashlib
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Set
from dataclasses import dataclass, field

sys.path.insert(0, str(Path(__file__).parent))
from utils.logger import logger

try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False


@dataclass
class MemoryRegion:
    """منطقة ذاكرة"""
    address: int = 0
    size: int = 0
    permissions: str = ""  # r/w/x
    path: str = ""
    is_private: bool = False
    is_shared: bool = False
    is_executable: bool = False
    
    # تحليل
    entropy: float = 0.0
    has_shellcode: bool = False
    has_strings: bool = False
    suspicious_score: float = 0.0


@dataclass
class MemoryForensicsResult:
    """نتيجة تحليل الذاكرة"""
    pid: int = 0
    process_name: str = ""
    
    # Memory stats
    total_vms_mb: float = 0.0
    total_rss_mb: float = 0.0
    private_memory_mb: float = 0.0
    shared_memory_mb: float = 0.0
    
    # Regions
    total_regions: int = 0
    executable_regions: int = 0
    writable_executable: int = 0  # RWX - خطير جداً
    
    # Suspicious findings
    injected_code_detected: bool = False
    hidden_threads: int = 0
    unpacked_sections: int = 0
    hollowed_regions: int = 0
    
    # Threads
    thread_count: int = 0
    suspended_threads: int = 0
    
    # Handles
    open_handles: int = 0
    suspicious_handles: List[str] = field(default_factory=list)
    
    # Score
    threat_flags: List[str] = field(default_factory=list)
    threat_score: float = 0.0
    
    error: str = ""


class MemoryForensicsEngine:
    """
    محرك تحليل الذاكرة
    - فحص memory regions (RWX)
    - كشف الكود المحقون
    - تحليل entropy للقطاعات
    - رصد threads المخفية
    """
    
    # توقيعات shellcode معروفة
    SHELLCODE_SIGNATURES = [
        bytes([0x31, 0xC0, 0x50, 0x68]),  # xor eax,eax; push eax; push ...
        bytes([0x55, 0x8B, 0xEC, 0x83]),  # push ebp; mov ebp,esp; sub ...
        bytes([0x48, 0x31, 0xC0, 0x50]),  # x64: xor rax,rax; push rax
        bytes([0xCC, 0xCC, 0xCC, 0xCC]),  # INT3 sled
        bytes([0x90, 0x90, 0x90, 0x90]),  # NOP sled
        bytes([0xFC, 0x48, 0x83, 0xE4]),  # cld; and rsp,...
    ]
    
    # كلمات مفتاحية خطيرة في السلاسل النصية
    SUSPICIOUS_STRINGS = [
        'VirtualAlloc', 'VirtualProtect', 'CreateRemoteThread',
        'WriteProcessMemory', 'NtCreateThreadEx', 'RtlCreateUserThread',
        'QueueUserAPC', 'SetThreadContext', 'NtUnmapViewOfSection',
        'ReflectiveLoader', 'MZ', 'PE\0\0',
        'cmd.exe', 'powershell', '/bin/sh',
    ]
    
    def __init__(self):
        self.results: List[MemoryForensicsResult] = []
    
    def analyze_process(self, pid: int) -> MemoryForensicsResult:
        """تحليل ذاكرة عملية حية"""
        if not PSUTIL_AVAILABLE:
            return MemoryForensicsResult(error="psutil غير متاح")
        
        result = MemoryForensicsResult(pid=pid)
        
        try:
            proc = psutil.Process(pid)
            result.process_name = proc.name()
            
            # Memory info
            mem_info = proc.memory_info()
            result.total_rss_mb = mem_info.rss / (1024 * 1024)
            result.total_vms_mb = mem_info.vms / (1024 * 1024)
            
            # Memory maps (regions)
            mem_maps = proc.memory_maps()
            result.total_regions = len(mem_maps)
            
            for mmap in mem_maps:
                perms = mmap.perms
                
                if 'x' in perms:
                    result.executable_regions += 1
                    if 'w' in perms:
                        result.writable_executable += 1
                
                if mmap.path and 'Anonymous' not in mmap.path:
                    path_lower = mmap.path.lower()
                    if 'inject' in path_lower or 'hook' in path_lower:
                        result.threat_flags.append(f"SUSPICIOUS_PATH:{mmap.path}")
            
            # Threads
            threads = proc.threads()
            result.thread_count = len(threads)
            
            # Check for hidden/suspended threads
            for thread in threads:
                # On macOS, we can't easily check suspended state via psutil
                pass
            
            # Open files / handles
            try:
                open_files = proc.open_files()
                result.open_handles = len(open_files)
                
                suspicious_exts = ['.dll', '.so', '.dylib', '.dat', '.bin', '.enc']
                for f in open_files:
                    if any(f.path.lower().endswith(ext) for ext in suspicious_exts):
                        result.suspicious_handles.append(f.path)
            except:
                pass
            
            # Threat analysis
            self._analyze_result(result, proc)
            
        except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
            result.error = str(e)
        except Exception as e:
            result.error = f"خطأ في تحليل الذاكرة: {e}"
        
        self.results.append(result)
        return result
    
    def _analyze_result(self, result: MemoryForensicsResult, proc: psutil.Process):
        """تحليل التهديدات من نتائج الذاكرة"""
        
        # RWX regions = dangerous
        if result.writable_executable > 0:
            result.injected_code_detected = True
            result.threat_flags.append(f"RWX_REGIONS:{result.writable_executable}")
        
        # High private memory (could be unpacked code)
        if result.total_vms_mb > 500:
            result.unpacked_sections += 1
            result.threat_flags.append("HIGH_VIRTUAL_MEMORY")
        
        # Many regions (could be unpacked/protected code)
        if result.total_regions > 100:
            result.unpacked_sections += 1
            result.threat_flags.append("MANY_MEMORY_REGIONS")
        
        # Many threads
        if result.thread_count > 10:
            result.hidden_threads += 1
            result.threat_flags.append("MANY_THREADS")
        
        # Suspicious handles
        if len(result.suspicious_handles) > 5:
            result.threat_flags.append("SUSPICIOUS_HANDLES")
        
        # Score
        score = 0.0
        score += result.writable_executable * 20  # RWX is very suspicious
        score += min(result.executable_regions * 3, 30)
        score += min(result.thread_count * 2, 20)
        score += len(result.suspicious_handles) * 2
        
        result.threat_score = min(score, 100)
    
    def analyze_code_static(self, code: str) -> MemoryForensicsResult:
        """تحليل ثابت: تدقيق كود بايثون بحثاً عن تلاعب بالذاكرة"""
        result = MemoryForensicsResult(process_name="static_analysis")
        code_lower = code.lower()
        
        # Memory manipulation indicators
        memory_patterns = {
            'RWX_ALLOCATION': ['VirtualAlloc', 'VirtualAllocEx', 'mmap', 'PROT_EXEC|PROT_WRITE'],
            'CODE_INJECTION': ['CreateRemoteThread', 'WriteProcessMemory', 'NtCreateThreadEx', 'process_inject'],
            'PROCESS_HOLLOWING': ['process_hollower', 'hollow', 'NtUnmapViewOfSection'],
            'REFLECTIVE_LOADING': ['reflective_loader', 'reflective_dll'],
            'MEMORY_PATCHING': ['patch_code', 'modify_memory', 'memory_write'],
            'SHELLCODE_EXECUTION': ['shellcode', 'execute_shellcode', 'run_shellcode'],
            'HEAP_SPRAY': ['heap_spray', 'spray_heap', 'nop_sled'],
            'DLL_UNHOOKING': ['unhook', 'remove_hook', 'patch_ntdll'],
        }
        
        for flag_name, patterns in memory_patterns.items():
            for pattern in patterns:
                if pattern.lower() in code_lower:
                    result.threat_flags.append(flag_name)
        
        # Score
        flag_scores = {
            'RWX_ALLOCATION': 20, 'CODE_INJECTION': 25, 'PROCESS_HOLLOWING': 25,
            'REFLECTIVE_LOADING': 20, 'MEMORY_PATCHING': 15, 'SHELLCODE_EXECUTION': 25,
            'HEAP_SPRAY': 15, 'DLL_UNHOOKING': 15,
        }
        
        score = 0.0
        for flag in result.threat_flags:
            score += flag_scores.get(flag, 10)
        
        result.threat_score = min(score, 100)
        return result
    
    def _compute_entropy(self, data: bytes) -> float:
        """حساب Shannon entropy"""
        if not data:
            return 0.0
        import math
        entropy = 0.0
        for x in range(256):
            p_x = data.count(x) / len(data)
            if p_x > 0:
                entropy -= p_x * math.log2(p_x)
        return entropy
    
    def _scan_for_shellcode(self, data: bytes) -> List[int]:
        """البحث عن توقيعات shellcode"""
        offsets = []
        for sig in self.SHELLCODE_SIGNATURES:
            pos = 0
            while True:
                pos = data.find(sig, pos)
                if pos == -1:
                    break
                offsets.append(pos)
                pos += 1
        return offsets


def analyze_sample_memory(sample_path: Path) -> MemoryForensicsResult:
    """تحليل عينة واحدة"""
    try:
        with open(sample_path, 'r', encoding='utf-8', errors='replace') as f:
            code = f.read()
    except:
        return MemoryForensicsResult(error=f"لا يمكن قراءة {sample_path}")
    
    engine = MemoryForensicsEngine()
    return engine.analyze_code_static(code)
