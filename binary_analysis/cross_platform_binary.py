"""
Nucleon v5.0 - Cross-Platform Binary Dissassembly Engine
تفكيك ثنائي متعدد المنصات: PE, ELF, Mach-O + تحليل تدفق التحكم
"""
import os
import sys
import json
import struct
import hashlib
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, field

sys.path.insert(0, str(Path(__file__).parent))
from utils.logger import logger

try:
    from capstone import Cs, CS_ARCH_X86, CS_MODE_32, CS_MODE_64, CS_ARCH_ARM, CS_MODE_ARM, CS_MODE_THUMB
    from capstone.x86 import X86_OP_REG, X86_OP_IMM, X86_OP_MEM
    CAPSTONE_AVAILABLE = True
except ImportError:
    CAPSTONE_AVAILABLE = False
    logger.warning("capstone غير مثبت. Binary disassembly محدود.")


@dataclass
class BinarySection:
    """قطاع ثنائي"""
    name: str = ""
    virtual_address: int = 0
    virtual_size: int = 0
    raw_size: int = 0
    raw_offset: int = 0
    characteristics: int = 0
    entropy: float = 0.0
    
    # تحليل
    is_executable: bool = False
    is_writable: bool = False
    is_readable: bool = True
    contains_code: bool = False
    suspicious_instructions: int = 0


@dataclass
class BinaryImport:
    """استدعاء خارجي"""
    dll_name: str = ""
    function_name: str = ""
    ordinal: int = 0
    
    # هل هو مريب؟
    is_suspicious: bool = False
    risk: str = ""


@dataclass
class BinaryAnalysisResult:
    """نتيجة تحليل ثنائي"""
    filepath: str = ""
    filetype: str = ""  # PE, ELF, MACHO
    architecture: str = ""  # x86, x64, ARM, ARM64
    
    # Hashes
    md5: str = ""
    sha1: str = ""
    sha256: str = ""
    
    # Sections
    sections: List[BinarySection] = field(default_factory=list)
    section_count: int = 0
    
    # Imports
    imports: List[BinaryImport] = field(default_factory=list)
    suspicious_imports: int = 0
    
    # Disassembly stats
    total_instructions: int = 0
    suspicious_instructions: int = 0
    
    # Threat
    threat_flags: List[str] = field(default_factory=list)
    threat_score: float = 0.0
    verdict: str = "CLEAN"
    
    error: str = ""


class BinaryAnalyzer:
    """
    محلل ثنائي متعدد المنصات
    - PE (Windows): pefile
    - ELF (Linux): pyelftools
    - Mach-O (macOS): تحليل يدوي
    - تفكيك: capstone (x86/x64/ARM)
    """
    
    # دوال API خطيرة
    SUSPICIOUS_APIS = {
        # Memory
        'VirtualAlloc', 'VirtualAllocEx', 'VirtualProtect', 'VirtualProtectEx',
        'HeapCreate', 'HeapAlloc', 'RtlAllocateHeap',
        
        # Process
        'CreateProcessA', 'CreateProcessW', 'CreateRemoteThread',
        'NtCreateThreadEx', 'RtlCreateUserThread', 'QueueUserAPC',
        
        # Injection
        'WriteProcessMemory', 'ReadProcessMemory', 'NtWriteVirtualMemory',
        'SetThreadContext', 'NtUnmapViewOfSection', 'NtMapViewOfSection',
        
        # Shell
        'WinExec', 'ShellExecuteA', 'ShellExecuteW', 'system',
        'popen', 'execve', 'CreateProcess',
        
        # Network
        'WSAStartup', 'socket', 'connect', 'send', 'recv',
        'InternetOpenA', 'InternetConnectA', 'HttpOpenRequestA',
        'URLDownloadToFileA',
        
        # Crypto
        'CryptEncrypt', 'CryptDecrypt', 'CryptAcquireContextA',
        'BCryptEncrypt', 'BCryptDecrypt',
        
        # Persistence
        'RegCreateKeyExA', 'RegSetValueExA', 'RegOpenKeyExA',
        'CreateServiceA', 'StartServiceA',
        
        # Anti-analysis
        'IsDebuggerPresent', 'CheckRemoteDebuggerPresent',
        'NtQueryInformationProcess', 'OutputDebugStringA',
        'GetTickCount', 'QueryPerformanceCounter', 'rdtsc',
    }
    
    # تواقيع بداية الملفات
    MAGIC_SIGNATURES = {
        b'MZ': 'PE',
        b'\x7fELF': 'ELF',
        b'\xfe\xed\xfa\xce': 'MACHO_32',
        b'\xfe\xed\xfa\xcf': 'MACHO_64',
        b'\xce\xfa\xed\xfe': 'MACHO_32_REV',
        b'\xcf\xfa\xed\xfe': 'MACHO_64_REV',
        b'\xca\xfe\xba\xbe': 'MACHO_FAT',
    }
    
    def __init__(self):
        self.capstone_md = None
    
    def _init_capstone(self, arch: str = 'x64'):
        """تهيئة capstone"""
        if not CAPSTONE_AVAILABLE:
            return
        
        arch_map = {
            'x86': (CS_ARCH_X86, CS_MODE_32),
            'x64': (CS_ARCH_X86, CS_MODE_64),
            'arm': (CS_ARCH_ARM, CS_MODE_ARM),
            'arm64': (CS_ARCH_ARM, CS_MODE_ARM),
        }
        
        cs_arch, cs_mode = arch_map.get(arch, (CS_ARCH_X86, CS_MODE_64))
        self.capstone_md = Cs(cs_arch, cs_mode)
        self.capstone_md.detail = True
    
    def analyze_file(self, filepath: Path) -> BinaryAnalysisResult:
        """تحليل ملف ثنائي كامل"""
        if not filepath.exists():
            return BinaryAnalysisResult(filepath=str(filepath), error="ملف غير موجود")
        
        try:
            with open(filepath, 'rb') as f:
                data = f.read()
        except Exception as e:
            return BinaryAnalysisResult(filepath=str(filepath), error=str(e))
        
        if len(data) < 4:
            return BinaryAnalysisResult(filepath=str(filepath), error="ملف صغير جداً")
        
        # Detect file type
        magic = data[:4]
        filetype = None
        for sig, ftype in self.MAGIC_SIGNATURES.items():
            if magic.startswith(sig):
                filetype = ftype
                break
        
        if not filetype:
            return BinaryAnalysisResult(
                filepath=str(filepath),
                filetype='UNKNOWN',
                error="صيغة غير معروفة"
            )
        
        result = BinaryAnalysisResult(
            filepath=str(filepath),
            filetype=filetype,
            md5=hashlib.md5(data).hexdigest(),
            sha1=hashlib.sha1(data).hexdigest(),
            sha256=hashlib.sha256(data).hexdigest(),
        )
        
        # Parse based on type
        if filetype == 'PE':
            self._analyze_pe(data, result)
        elif filetype.startswith('ELF'):
            self._analyze_elf(data, result)
        elif 'MACHO' in filetype:
            self._analyze_macho(data, result)
        
        # Compute threat score
        self._compute_threat(result)
        
        return result
    
    def _analyze_pe(self, data: bytes, result: BinaryAnalysisResult):
        """تحليل PE"""
        try:
            import pefile
            pe = pefile.PE(data=data)
            result.architecture = 'x64' if pe.FILE_HEADER.Machine == 0x8664 else 'x86'
            
            # Sections
            for section in pe.sections:
                name = section.Name.decode('utf-8', errors='replace').rstrip('\x00')
                sec = BinarySection(
                    name=name,
                    virtual_address=section.VirtualAddress,
                    virtual_size=section.Misc_VirtualSize,
                    raw_size=section.SizeOfRawData,
                    raw_offset=section.PointerToRawData,
                    characteristics=section.Characteristics,
                    entropy=self._compute_section_entropy(section.get_data()),
                )
                
                # Section permissions
                characteristics = section.Characteristics
                sec.is_executable = bool(characteristics & 0x20000000)
                sec.is_writable = bool(characteristics & 0x80000000)
                sec.is_readable = bool(characteristics & 0x40000000)
                
                if sec.is_executable:
                    sec.contains_code = True
                    
                    # Disassemble this section
                    if CAPSTONE_AVAILABLE:
                        self._init_capstone(result.architecture)
                        if self.capstone_md:
                            section_data = section.get_data()
                            for insn in self.capstone_md.disasm(section_data, 0):
                                result.total_instructions += 1
                
                result.sections.append(sec)
            
            result.section_count = len(result.sections)
            
            # Imports
            if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
                for entry in pe.DIRECTORY_ENTRY_IMPORT:
                    dll_name = entry.dll.decode('utf-8', errors='replace') if entry.dll else ''
                    for imp in entry.imports:
                        func_name = imp.name.decode('utf-8', errors='replace') if imp.name else f"ord_{imp.ordinal}"
                        
                        bin_imp = BinaryImport(
                            dll_name=dll_name,
                            function_name=func_name,
                            ordinal=imp.ordinal or 0,
                        )
                        
                        if func_name in self.SUSPICIOUS_APIS or any(
                            s in func_name.lower() for s in ['inject', 'hook', 'shellcode', 'keylog']
                        ):
                            bin_imp.is_suspicious = True
                            result.suspicious_imports += 1
                        
                        result.imports.append(bin_imp)
        
        except ImportError:
            logger.warning("pefile غير مثبت - تحليل PE محدود")
            result.error = "pefile غير متاح"
    
    def _analyze_elf(self, data: bytes, result: BinaryAnalysisResult):
        """تحليل ELF"""
        try:
            from elftools.elf.elffile import ELFFile
            from io import BytesIO
            
            elf = ELFFile(BytesIO(data))
            
            # Architecture
            arch_map = {
                'EM_X86_64': 'x64',
                'EM_386': 'x86',
                'EM_ARM': 'arm',
                'EM_AARCH64': 'arm64',
            }
            result.architecture = arch_map.get(elf['e_machine'], 'unknown')
            
            # Sections
            for section in elf.iter_sections():
                sec = BinarySection(
                    name=section.name,
                    virtual_address=section['sh_addr'],
                    virtual_size=section['sh_size'],
                    raw_offset=section['sh_offset'],
                )
                
                flags = section['sh_flags']
                sec.is_executable = bool(flags & 0x4)
                sec.is_writable = bool(flags & 0x1)
                
                if section.data():
                    sec.entropy = self._compute_section_entropy(section.data())
                
                result.sections.append(sec)
            
            result.section_count = len(result.sections)
            
            # Symbol table (imports)
            try:
                symbols = elf.get_section_by_name('.dynsym')
                if symbols:
                    for sym in symbols.iter_symbols():
                        if sym.name and sym['st_shndx'] == 'SHN_UNDEF':
                            bin_imp = BinaryImport(
                                function_name=sym.name,
                            )
                            if sym.name in self.SUSPICIOUS_APIS:
                                bin_imp.is_suspicious = True
                                result.suspicious_imports += 1
                            result.imports.append(bin_imp)
            except:
                pass
        
        except ImportError:
            logger.warning("pyelftools غير مثبت - تحليل ELF محدود")
            result.error = "pyelftools غير متاح"
    
    def _analyze_macho(self, data: bytes, result: BinaryAnalysisResult):
        """تحليل Mach-O (يدوي)"""
        result.architecture = 'x64' if b'\xcf\xfa\xed\xfe' in data[:4] else 'x86'
        
        # Mach-O header parsing (simplified)
        try:
            magic = struct.unpack('<I', data[:4])[0]
            
            if magic in (0xFEEDFACE, 0xCEFAEDFE):  # 32-bit
                header_size = 28
                cpu_type = struct.unpack('<I', data[4:8])[0]
                cpu_map = {7: 'x86', 12: 'arm', 16777223: 'x64', 16777228: 'arm64'}
                result.architecture = cpu_map.get(cpu_type, 'unknown')
                
                ncmds = struct.unpack('<I', data[16:20])[0]
                
                # Parse load commands for sections
                offset = header_size
                for _ in range(min(ncmds, 50)):
                    if offset + 8 > len(data):
                        break
                    cmd = struct.unpack('<I', data[offset:offset+4])[0]
                    cmdsize = struct.unpack('<I', data[offset+4:offset+8])[0]
                    
                    if cmd == 0x19:  # LC_SEGMENT_64
                        segname = data[offset+8:offset+24].decode('utf-8', errors='replace').rstrip('\x00')
                        nsects = struct.unpack('<I', data[offset+64:offset+68])[0]
                        
                        sect_offset = offset + 72
                        for _ in range(nsects):
                            if sect_offset + 80 > len(data):
                                break
                            sectname = data[sect_offset:sect_offset+16].decode('utf-8', errors='replace').rstrip('\x00')
                            
                            sec = BinarySection(name=f"{segname}.{sectname}")
                            result.sections.append(sec)
                            sect_offset += 80
                    
                    offset += cmdsize
            
            result.section_count = len(result.sections)
        
        except Exception as e:
            result.error = f"خطأ في تحليل Mach-O: {e}"
    
    def _compute_section_entropy(self, data: bytes) -> float:
        """حساب entropy القطاع"""
        if not data:
            return 0.0
        import math
        entropy = 0.0
        for x in range(256):
            p_x = data.count(x) / len(data)
            if p_x > 0:
                entropy -= p_x * math.log2(p_x)
        return entropy
    
    def _compute_threat(self, result: BinaryAnalysisResult):
        """حساب درجة التهديد"""
        score = 0.0
        
        # Suspicious imports
        score += result.suspicious_imports * 15
        
        # Suspicious sections
        for sec in result.sections:
            if sec.is_executable and sec.is_writable:
                result.threat_flags.append(f"RWX_SECTION:{sec.name}")
                score += 20
            
            if sec.entropy > 7.0:  # High entropy = packed/encrypted
                result.threat_flags.append(f"HIGH_ENTROPY:{sec.name}")
                score += 15
            
            if sec.name.lower() in ['.textbss', '.coded', '.inject']:
                result.threat_flags.append(f"SUSPICIOUS_SECTION:{sec.name}")
                score += 10
        
        result.threat_score = min(score, 100)
        
        if result.threat_score >= 50:
            result.verdict = "MALICIOUS"
        elif result.threat_score >= 25:
            result.verdict = "SUSPICIOUS"
        else:
            result.verdict = "CLEAN"
    
    def disassemble_bytes(self, code: bytes, arch: str = 'x64') -> List[str]:
        """تفكيك bytes إلى assembly"""
        if not CAPSTONE_AVAILABLE:
            return ["[capstone غير متاح]"]
        
        self._init_capstone(arch)
        if not self.capstone_md:
            return ["[فشل تهيئة capstone]"]
        
        instructions = []
        for insn in self.capstone_md.disasm(code, 0x1000):
            instructions.append(f"0x{insn.address:x}: {insn.mnemonic} {insn.op_str}")
        
        return instructions
    
    def scan_strings(self, data: bytes, min_length: int = 4) -> List[str]:
        """استخراج السلاسل النصية"""
        strings = []
        current = b""
        
        for byte in data:
            if 0x20 <= byte <= 0x7E:
                current += bytes([byte])
            else:
                if len(current) >= min_length:
                    strings.append(current.decode('ascii', errors='replace'))
                current = b""
        
        return strings


def analyze_binary_file(filepath: Path) -> BinaryAnalysisResult:
    """تحليل ملف ثنائي واحد"""
    analyzer = BinaryAnalyzer()
    return analyzer.analyze_file(filepath)
