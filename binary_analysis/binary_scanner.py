"""
Binary Analysis Engine v4.0
محرك تحليل الملفات الثنائية PE/ELF/Mach-O

Academic Research: Static binary analysis without execution
يدعم استخراج الرؤوس، الاستيرادات، السلاسل، والأنماط المشبوهة
"""

import os
import sys
import re
import hashlib
import struct
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, field
from collections import defaultdict

sys.path.insert(0, str(Path(__file__).parent.parent))
from utils.logger import logger

# Optional imports
try:
    import pefile
    PE_AVAILABLE = True
except ImportError:
    PE_AVAILABLE = False
    logger.warning("pefile غير مثبت. تحليل PE محدود.")

try:
    from elftools.elf.elffile import ELFFile
    from elftools.elf.sections import SymbolTableSection
    ELF_AVAILABLE = True
except ImportError:
    ELF_AVAILABLE = False
    logger.warning("pyelftools غير مثبت. تحليل ELF محدود.")


@dataclass
class BinaryInfo:
    """Binary file information"""
    filepath: str = ""
    filename: str = ""
    filetype: str = ""  # PE, ELF, Mach-O, Unknown
    filesize: int = 0
    
    # Hashes
    md5: str = ""
    sha1: str = ""
    sha256: str = ""
    
    # PE specific
    is_pe: bool = False
    pe_machine: str = ""
    pe_timestamp: int = 0
    pe_subsystem: str = ""
    pe_sections: List[Dict] = field(default_factory=list)
    pe_imports: List[str] = field(default_factory=list)
    pe_exports: List[str] = field(default_factory=list)
    pe_characteristics: List[str] = field(default_factory=list)
    pe_entry_point: int = 0
    pe_image_base: int = 0
    
    # ELF specific
    is_elf: bool = False
    elf_machine: str = ""
    elf_type: str = ""
    elf_interp: str = ""
    elf_sections: List[Dict] = field(default_factory=list)
    elf_symbols: List[str] = field(default_factory=list)
    
    # MACH-O specific
    is_macho: bool = False
    macho_cpu: str = ""
    macho_type: str = ""
    
    # General analysis
    strings: List[str] = field(default_factory=list)
    suspicious_strings: List[str] = field(default_factory=list)
    entropy: float = 0.0
    
    # Threat assessment
    threat_score: float = 0.0
    threat_level: str = "CLEAN"
    threat_flags: List[str] = field(default_factory=list)


class BinaryAnalyzer:
    """
    Multi-format binary analyzer
    Supports PE, ELF, and Mach-O formats
    """
    
    # Suspicious PE imports
    SUSPICIOUS_PE_IMPORTS = {
        'critical': {
            'VirtualAlloc', 'VirtualAllocEx', 'VirtualProtect',
            'WriteProcessMemory', 'CreateRemoteThread',
            'NtCreateProcess', 'NtCreateThread', 'RtlCreateUserThread',
            'SetWindowsHookEx', 'UnhookWindowsHookEx',
        },
        'high': {
            'OpenProcess', 'ReadProcessMemory', 'CreateFileMapping',
            'MapViewOfFile', 'NtMapViewOfSection',
            'CreateToolhelp32Snapshot', 'Process32First',
            'Process32Next', 'Module32First', 'Thread32First',
            'RegOpenKeyEx', 'RegSetValueEx', 'RegCreateKeyEx',
        },
        'medium': {
            'socket', 'connect', 'send', 'recv', 'listen',
            'InternetOpen', 'HttpOpenRequest', 'URLDownloadToFile',
            'WinHttpOpen', 'WinHttpConnect', 'WinHttpOpenRequest',
            'CreateProcess', 'ShellExecute', 'WinExec',
            'LoadLibrary', 'GetProcAddress', 'FreeLibrary',
        },
    }
    
    # Suspicious strings in binaries
    SUSPICIOUS_STRINGS = [
        'cmd.exe', 'powershell', 'wscript', 'cscript',
        'regsvr32', 'rundll32', 'mshta', 'certutil',
        'schtasks', 'sc ', 'net user', 'net group',
        'add administrator', 'disable defender',
        'bypass', 'shellcode', 'payload', 'inject',
        'hack', 'crack', 'trojan', 'malware',
        'ransom', 'keylog', 'spy', 'steal',
        'backdoor', 'rootkit', 'exploit',
        'calc.exe', 'notepad.exe', 'svchost.exe',
        '/bin/sh', '/bin/bash', 'nc -e', 'mkfifo',
        'curl ', 'wget ', 'python -c', 'perl -e',
        'ruby -e ', 'base64 -d', 'base64 --decode',
    ]
    
    # PE section entropy thresholds
    HIGH_ENTROPY_SECTIONS = {'.text', '.data', '.rdata'}
    
    def __init__(self):
        self.results: List[BinaryInfo] = []
    
    def analyze_file(self, filepath: Path) -> BinaryInfo:
        """Analyze a single binary file"""
        info = BinaryInfo()
        info.filepath = str(filepath)
        info.filename = filepath.name
        info.filesize = filepath.stat().st_size
        
        # Calculate hashes
        with open(filepath, 'rb') as f:
            data = f.read()
        
        info.md5 = hashlib.md5(data).hexdigest()
        info.sha1 = hashlib.sha1(data).hexdigest()
        info.sha256 = hashlib.sha256(data).hexdigest()
        
        # Determine file type
        magic = data[:4]
        if magic[:2] == b'MZ':
            info.filetype = "PE"
            info.is_pe = True
            self._analyze_pe(info, data)
        elif magic[:4] == b'\x7fELF':
            info.filetype = "ELF"
            info.is_elf = True
            self._analyze_elf(info, filepath, data)
        elif magic[:4] in (b'\xfe\xed\xfa\xce', b'\xfe\xed\xfa\xcf',
                            b'\xce\xfa\xed\xfe', b'\xcf\xfa\xed\xfe'):
            info.filetype = "Mach-O"
            info.is_macho = True
            self._analyze_macho(info, data)
        else:
            info.filetype = "Unknown"
        
        # String extraction
        self._extract_strings(info, data)
        
        # Entropy calculation
        info.entropy = self._calculate_entropy(data)
        
        # Threat assessment
        self._assess_threat(info)
        
        self.results.append(info)
        return info
    
    def _analyze_pe(self, info: BinaryInfo, data: bytes):
        """Analyze PE (Portable Executable) files"""
        if not PE_AVAILABLE:
            logger.warning("pefile غير متاح. تحليل PE محدود.")
            return
        
        try:
            pe = pefile.PE(data=data)
            
            # Machine type
            machine_types = {
                0x14c: 'i386', 0x8664: 'AMD64',
                0x1c0: 'ARM', 0xaa64: 'ARM64',
            }
            info.pe_machine = machine_types.get(
                pe.FILE_HEADER.Machine, f"0x{pe.FILE_HEADER.Machine:04x}"
            )
            
            # Timestamp
            info.pe_timestamp = pe.FILE_HEADER.TimeDateStamp
            
            # Subsystem
            subsystem_types = {
                2: 'GUI', 3: 'Console', 1: 'Native',
            }
            info.pe_subsystem = subsystem_types.get(
                pe.OPTIONAL_HEADER.Subsystem, 'Unknown'
            )
            
            # Entry point
            info.pe_entry_point = pe.OPTIONAL_HEADER.AddressOfEntryPoint
            info.pe_image_base = pe.OPTIONAL_HEADER.ImageBase
            
            # Characteristics
            characteristics = {
                0x0002: 'EXECUTABLE_IMAGE',
                0x0020: 'LARGE_ADDRESS_AWARE',
                0x0100: '32BIT_MACHINE',
                0x2000: 'DLL',
                0x4000: 'SYSTEM',
            }
            for flag, name in characteristics.items():
                if pe.FILE_HEADER.Characteristics & flag:
                    info.pe_characteristics.append(name)
            
            # Sections analysis
            for section in pe.sections:
                sec_data = section.get_data()
                sec_entropy = self._calculate_entropy(sec_data)
                
                sec_info = {
                    'name': section.Name.decode('utf-8', errors='replace').strip('\x00'),
                    'virtual_address': section.VirtualAddress,
                    'virtual_size': section.Misc_VirtualSize,
                    'raw_size': section.SizeOfRawData,
                    'entropy': sec_entropy,
                    'characteristics': section.Characteristics,
                }
                info.pe_sections.append(sec_info)
                
                if sec_entropy > 7.0:
                    flags = info.threat_flags
                    flags.append(f"high_entropy_section:{sec_info['name']}")
                    info.threat_flags = flags
            
            # Imports
            if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
                for entry in pe.DIRECTORY_ENTRY_IMPORT:
                    dll_name = entry.dll.decode('utf-8', errors='replace')
                    for imp in entry.imports:
                        if imp.name:
                            func_name = imp.name.decode('utf-8', errors='replace')
                            info.pe_imports.append(f"{dll_name}!{func_name}")
            
            # Exports
            if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
                for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                    if exp.name:
                        info.pe_exports.append(
                            exp.name.decode('utf-8', errors='replace')
                        )
            
            logger.info(f"PE analysis: {info.filename} ({len(info.pe_imports)} imports)")
            
        except Exception as e:
            logger.error(f"PE analysis error: {e}")
            info.threat_flags.append(f"pe_parse_error:{e}")
    
    def _analyze_elf(self, info: BinaryInfo, filepath: Path, data: bytes):
        """Analyze ELF (Executable and Linkable Format) files"""
        if not ELF_AVAILABLE:
            logger.warning("pyelftools غير متاح. تحليل ELF محدود.")
            return
        
        try:
            with open(filepath, 'rb') as f:
                elf = ELFFile(f)
            
            # Machine type
            machine_types = {
                'EM_386': 'i386', 'EM_X86_64': 'x86_64',
                'EM_ARM': 'ARM', 'EM_AARCH64': 'ARM64',
                'EM_MIPS': 'MIPS',
            }
            info.elf_machine = machine_types.get(
                elf['e_machine'], elf['e_machine']
            )
            
            # ELF type
            elf_types = {
                'ET_EXEC': 'Executable', 'ET_DYN': 'Shared Object',
                'ET_REL': 'Relocatable',
            }
            info.elf_type = elf_types.get(elf['e_type'], elf['e_type'])
            
            # Interpreter
            for seg in elf.iter_segments():
                if seg['p_type'] == 'PT_INTERP':
                    info.elf_interp = seg.data().decode('utf-8', errors='replace').strip('\x00')
            
            # Sections
            for section in elf.iter_sections():
                sec_data = section.data()
                sec_info = {
                    'name': section.name,
                    'type': section['sh_type'],
                    'size': section['sh_size'],
                    'entropy': self._calculate_entropy(sec_data) if sec_data else 0,
                }
                info.elf_sections.append(sec_info)
                
                if sec_info['entropy'] > 7.0:
                    flags = info.threat_flags
                    flags.append(f"high_entropy_section:{section.name}")
                    info.threat_flags = flags
            
            # Symbols
            for section in elf.iter_sections():
                if isinstance(section, SymbolTableSection):
                    for symbol in section.iter_symbols():
                        if symbol.name:
                            info.elf_symbols.append(symbol.name)
            
            logger.info(f"ELF analysis: {info.filename} ({len(info.elf_symbols)} symbols)")
            
        except Exception as e:
            logger.error(f"ELF analysis error: {e}")
            info.threat_flags.append(f"elf_parse_error:{e}")
    
    def _analyze_macho(self, info: BinaryInfo, data: bytes):
        """Analyze Mach-O files (macOS)"""
        try:
            magic = struct.unpack('<I', data[:4])[0]
            
            cpu_types = {
                0x7: 'i386', 0x1000007: 'x86_64',
                0xc: 'ARM', 0x100000c: 'ARM64',
            }
            info.macho_cpu = cpu_types.get(magic, f"0x{magic:08x}")
            
            # Determine file type from header
            file_types = {
                0x1: 'MH_OBJECT', 0x2: 'MH_EXECUTE',
                0x6: 'MH_DYLIB', 0x8: 'MH_BUNDLE',
            }
            if len(data) > 16:
                filetype = struct.unpack('<I', data[12:16])[0]
                info.macho_type = file_types.get(filetype, f"0x{filetype:08x}")
            
            logger.info(f"Mach-O analysis: {info.filename}")
            
        except Exception as e:
            logger.error(f"Mach-O analysis error: {e}")
    
    def _extract_strings(self, info: BinaryInfo, data: bytes, min_length: int = 4):
        """Extract printable strings from binary data"""
        pattern = rb'[\x20-\x7e]{' + str(min_length).encode() + rb',}'
        strings = re.findall(pattern, data)
        
        decoded = []
        for s in strings:
            try:
                decoded.append(s.decode('ascii'))
            except:
                pass
        
        info.strings = decoded
        info.suspicious_strings = [
            s for s in decoded
            if any(susp.lower() in s.lower() for susp in self.SUSPICIOUS_STRINGS)
        ]
    
    def _calculate_entropy(self, data: bytes) -> float:
        """Calculate Shannon entropy of data"""
        if not data:
            return 0.0
        
        import math
        entropy = 0.0
        length = len(data)
        
        freq = {}
        for byte in data:
            freq[byte] = freq.get(byte, 0) + 1
        
        for count in freq.values():
            p = count / length
            entropy -= p * math.log2(p)
        
        return entropy
    
    def _assess_threat(self, info: BinaryInfo):
        """Assess threat level of binary"""
        score = 0.0
        
        # PE-specific threat scoring
        if info.is_pe:
            # Check suspicious imports
            for imp in info.pe_imports:
                imp_name = imp.split('!')[-1] if '!' in imp else imp
                
                for level, funcs in self.SUSPICIOUS_PE_IMPORTS.items():
                    if imp_name in funcs:
                        if level == 'critical':
                            score += 15
                            info.threat_flags.append(f"critical_import:{imp_name}")
                        elif level == 'high':
                            score += 8
                            info.threat_flags.append(f"high_risk_import:{imp_name}")
                        elif level == 'medium':
                            score += 4
            
            # Check high-entropy sections
            for section in info.pe_sections:
                if section['entropy'] > 7.5:
                    score += 10
                    info.suspicious_strings.append(
                        f"high_entropy:{section['name']}:{section['entropy']:.1f}"
                    )
                elif section['entropy'] > 6.5:
                    score += 5
            
            # Check entry point in unusual sections
            ep_in_code = any(
                section['virtual_address'] <= info.pe_entry_point <
                (section['virtual_address'] + section['virtual_size'])
                and section['name'] == '.text'
                for section in info.pe_sections
            )
            if not ep_in_code and info.pe_sections:
                score += 8
                info.threat_flags.append("suspicious_entry_point")
        
        # ELF-specific threat scoring
        if info.is_elf:
            suspicious_syms = {'ptrace', 'exec', 'fork', 'system',
                               'popen', 'dlopen', 'dlsym'}
            for sym in info.elf_symbols:
                if sym in suspicious_syms:
                    score += 5
                    info.threat_flags.append(f"suspicious_symbol:{sym}")
            
            # Static binary (no interpreter) - common in malware
            if not info.elf_interp and info.elf_type == 'Executable':
                score += 5
        
        # String-based scoring
        for s in info.suspicious_strings:
            susp_lower = s.lower()
            if any(x in susp_lower for x in ['shell', 'cmd', 'exec', 'popen']):
                score += 3
            if any(x in susp_lower for x in ['inject', 'hook', 'hollow']):
                score += 5
            if any(x in susp_lower for x in ['ransom', 'encrypt', 'decrypt']):
                score += 8
        
        # Entropy-based scoring
        if info.entropy > 7.5:
            score += 10
        elif info.entropy > 6.5:
            score += 5
        
        info.threat_score = min(score, 100)
        
        if info.threat_score >= 60:
            info.threat_level = "MALICIOUS"
        elif info.threat_score >= 30:
            info.threat_level = "SUSPICIOUS"
        else:
            info.threat_level = "CLEAN"
    
    def analyze_directory(self, directory: Path) -> List[BinaryInfo]:
        """Analyze all binaries in a directory"""
        results = []
        
        extensions = {'.exe', '.dll', '.sys', '.ocx', '.elf', '.so', '.o',
                      '.bin', '.dat', '.dylib', '.mach-o'}
        
        for filepath in directory.rglob('*'):
            if filepath.is_file() and filepath.suffix.lower() in extensions:
                try:
                    result = self.analyze_file(filepath)
                    results.append(result)
                except Exception as e:
                    logger.error(f"Error analyzing {filepath}: {e}")
        
        return results
    
    def get_summary(self) -> Dict:
        """Get summary of all analyzed binaries"""
        total = len(self.results)
        malicious = sum(1 for r in self.results if r.threat_level == "MALICIOUS")
        suspicious = sum(1 for r in self.results if r.threat_level == "SUSPICIOUS")
        clean = sum(1 for r in self.results if r.threat_level == "CLEAN")
        
        return {
            'total': total,
            'malicious': malicious,
            'suspicious': suspicious,
            'clean': clean,
            'detection_rate': malicious / total if total > 0 else 0,
            'results': self.results,
        }


def main():
    """CLI entry point for binary analysis"""
    import argparse
    
    parser = argparse.ArgumentParser(description="Nucleon Binary Analyzer")
    parser.add_argument("path", help="Path to binary file or directory")
    parser.add_argument("--output", help="Output JSON report path")
    
    args = parser.parse_args()
    
    analyzer = BinaryAnalyzer()
    target = Path(args.path)
    
    if target.is_file():
        result = analyzer.analyze_file(target)
        print(f"\n{'='*60}")
        print(f"  {result.filename} - {result.filetype}")
        print(f"  Threat: {result.threat_level} ({result.threat_score:.1f})")
        print(f"  MD5: {result.md5}")
        print(f"  SHA256: {result.sha256}")
        if result.suspicious_strings:
            print(f"\n  Suspicious Strings ({len(result.suspicious_strings)}):")
            for s in result.suspicious_strings[:5]:
                print(f"    - {s}")
        print(f"{'='*60}\n")
    else:
        results = analyzer.analyze_directory(target)
        summary = analyzer.get_summary()
        print(f"\nAnalyzed {summary['total']} files:")
        print(f"  Malicious:  {summary['malicious']}")
        print(f"  Suspicious: {summary['suspicious']}")
        print(f"  Clean:      {summary['clean']}")


if __name__ == "__main__":
    main()
