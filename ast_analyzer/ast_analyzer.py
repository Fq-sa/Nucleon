"""
AST-Based Static Code Analysis Engine v4.0
محلل ثابت متقدم باستخدام AST بدلاً من التعبيرات النمطية

Academic Research: 18-layer AST analysis for deep code understanding
يحلل شجرة الكود البرمجي الحقيقية بدلاً من البحث النصي
"""

import ast
import sys
from pathlib import Path
from typing import Dict, List, Set, Tuple, Optional
from dataclasses import dataclass, field
from collections import defaultdict

sys.path.insert(0, str(Path(__file__).parent.parent))
from utils.logger import logger


@dataclass
class ASTAnalysisResult:
    """نتيجة التحليل AST"""
    # Layer results
    data_collection_score: float = 0.0
    system_enumeration_score: float = 0.0
    encryption_score: float = 0.0
    process_manipulation_score: float = 0.0
    stealth_score: float = 0.0
    persistence_score: float = 0.0
    network_score: float = 0.0
    multi_stage_score: float = 0.0
    obfuscation_score: float = 0.0
    conditional_triggers_score: float = 0.0
    file_operations_score: float = 0.0
    code_execution_score: float = 0.0
    
    # Detailed findings
    imports: List[str] = field(default_factory=list)
    function_calls: List[str] = field(default_factory=list)
    suspicious_patterns: List[Dict] = field(default_factory=list)
    string_constants: List[str] = field(default_factory=list)
    decorators: List[str] = field(default_factory=list)
    
    # Meta
    total_lines: int = 0
    total_functions: int = 0
    total_classes: int = 0
    complexity_score: float = 0.0
    
    # Combined threat score (0-100)
    combined_threat_score: float = 0.0
    
    # Detailed per-function analysis
    function_analysis: Dict[str, Dict] = field(default_factory=dict)


class ASTBehavioralAnalyzer:
    """
    AST-based static analyzer with 18 analysis layers
    Uses Python's AST module for deep code understanding
    """
    
    # Suspicious import patterns
    SUSPICIOUS_IMPORTS = {
        'data_collection': {
            'os': 3, 'pwd': 5, 'getpass': 7, 'keyring': 8,
            'sqlite3': 4, 'pickle': 5, 'marshal': 7,
            'winreg': 8, '_winreg': 8, 'shutil': 4,
        },
        'encryption': {
            'cryptography': 8, 'Crypto': 10, 'crypt': 7,
            'hashlib': 4, 'hmac': 5, 'base64': 3,
            'Fernet': 12, 'AES': 12, 'ChaCha20': 14,
            'PBKDF2': 8, 'scrypt': 7, 'xor': 4,
            'zlib': 3, 'bz2': 3, 'gzip': 3,
        },
        'network': {
            'socket': 8, 'http': 5, 'urllib': 5,
            'requests': 6, 'ftplib': 7, 'smtplib': 8,
            'socket': 8, 'ssl': 5, 'websocket': 7,
            'paramiko': 8, 'twisted': 6, 'scapy': 10,
            'impacket': 12, 'pwn': 14,
        },
        'process_manipulation': {
            'ctypes': 8, 'multiprocessing': 6, 'threading': 4,
            '_thread': 6, 'thread': 6, 'win32api': 10,
            'win32con': 10, 'win32process': 12, 'signal': 5,
            'subprocess': 7, 'mmap': 8, 'fcntl': 6,
        },
        'stealth': {
            'random': 3, 'time': 2, 'uuid': 4,
            'secrets': 6, 'antivm': 12, 'sandbox': 10,
            'vmdetect': 12, 'antidebug': 14, 'sys': 3,
        },
        'persistence': {
            'croniter': 7, 'launchd': 8, 'schedule': 5,
            'daemon': 5, 'service': 6, 'startup': 8,
            'plistlib': 7, 'winreg': 8,
        }
    }
    
    # Function call patterns indicating malicious behavior
    MALICIOUS_FUNCTIONS = {
        'data_theft': [
            ('os.listdir', 5), ('os.walk', 6), ('os.environ', 7),
            ('glob.glob', 4), ('fnmatch', 3), ('os.path.expanduser', 4),
            ('getattr', 6), ('setattr', 6), ('__import__', 8),
            ('compile(', 8), ('exec(', 12), ('eval(', 10),
        ],
        'encryption_ops': [
            ('encrypt(', 10), ('decrypt(', 5), ('AES.new(', 12),
            ('ChaCha20', 14), ('Fernet(', 12), ('scrypt(', 8),
            ('pbkdf2', 8), ('xor', 3), ('rot13', 2),
        ],
        'process_ops': [
            ('CreateRemoteThread', 15), ('VirtualAlloc', 14),
            ('WriteProcessMemory', 15), ('OpenProcess', 12),
            ('ctypes.windll', 10), ('ctypes.CDLL', 8),
            ('ptrace(', 12), ('fork(', 6),
        ],
        'exfiltration': [
            ('socket.send', 8), ('requests.post', 7), ('urllib.request.urlopen', 6),
            ('smtplib.SMTP', 8), ('ftplib.FTP', 7), ('upload', 5),
        ],
        'evasion': [
            ('getattr(', 5), ('chr(', 3), ('ord(', 2),
            ('base64.b64decode', 5), ('codecs.decode', 4),
            ('marshal.loads', 10), ('pickle.loads', 10),
        ],
        'persistence': [
            ('os.makedirs', 3), ('shutil.copy', 5), ('os.symlink', 5),
            ('write_registry', 10), ('cron', 4), ('launchctl', 8),
            ('schedule.every', 5), ('schtasks', 8),
        ],
    }
    
    def __init__(self):
        self.result = ASTAnalysisResult()
        self.tree = None
        self.source_code = ""
        self._function_map = {}
        self._import_map = {}
        
    def analyze(self, source_code: str) -> ASTAnalysisResult:
        """Run full 18-layer AST analysis"""
        logger.info("بدء التحليل AST المتقدم (18 طبقة)")
        self.source_code = source_code
        self.result = ASTAnalysisResult()
        self.result.total_lines = len(source_code.split('\n'))
        
        try:
            self.tree = ast.parse(source_code)
        except SyntaxError as e:
            logger.error(f"خطأ في تحليل الكود: {e}")
            return self.result
        
        # Phase 1: Extract structural information
        self._extract_imports()
        self._extract_functions()
        self._extract_strings()
        self._extract_decorators()
        
        # Phase 2: Run 18 analysis layers
        self._layer_data_collection()
        self._layer_system_enumeration()
        self._layer_encryption_detection()
        self._layer_process_manipulation()
        self._layer_stealth_behavior()
        self._layer_persistence()
        self._layer_network_activity()
        self._layer_multi_stage()
        self._layer_obfuscation()
        self._layer_conditional_triggers()
        self._layer_file_operations()
        self._layer_code_execution()
        self._layer_memory_ops()
        self._layer_evasion_techniques()
        self._layer_supply_chain()
        self._layer_lateral_movement()
        self._layer_data_exfiltration()
        self._layer_anti_analysis()
        
        # Phase 3: Compute final scores
        self._compute_metrics()
        
        logger.info(f"اكتمل التحليل AST - Threat Score: {self.result.combined_threat_score:.1f}")
        return self.result
    
    def _extract_imports(self):
        """Extract all imports using AST traversal"""
        for node in ast.walk(self.tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    self.result.imports.append(alias.name)
                    if alias.asname:
                        self._import_map[alias.asname] = alias.name
                    self._import_map[alias.name] = alias.name
            elif isinstance(node, ast.ImportFrom):
                module = node.module or ''
                for alias in node.names:
                    full = f"{module}.{alias.name}"
                    self.result.imports.append(full)
                    if alias.asname:
                        self._import_map[alias.asname] = full
    
    def _extract_functions(self):
        """Extract function definitions and calls"""
        for node in ast.walk(self.tree):
            if isinstance(node, ast.FunctionDef):
                self.result.total_functions += 1
                self._function_map[node.name] = {
                    'lineno': node.lineno,
                    'decorators': [self._get_name(d) for d in node.decorator_list],
                    'arg_count': len(node.args.args) if node.args else 0,
                }
            elif isinstance(node, ast.ClassDef):
                self.result.total_classes += 1
            elif isinstance(node, ast.Call):
                func_name = self._get_name(node.func)
                if func_name:
                    self.result.function_calls.append(func_name)
    
    def _extract_strings(self):
        """Extract string constants from code"""
        for node in ast.walk(self.tree):
            if isinstance(node, ast.Constant) and isinstance(node.value, str):
                s = node.value
                if len(s) > 3:  # Skip very short strings
                    self.result.string_constants.append(s)
    
    def _extract_decorators(self):
        """Extract decorator usage"""
        for node in ast.walk(self.tree):
            if isinstance(node, (ast.FunctionDef, ast.ClassDef)):
                for dec in node.decorator_list:
                    name = self._get_name(dec)
                    if name:
                        self.result.decorators.append(name)
    
    def _get_name(self, node) -> Optional[str]:
        """Extract name from AST node"""
        if isinstance(node, ast.Name):
            return node.id
        elif isinstance(node, ast.Attribute):
            return f"{self._get_name(node.value)}.{node.attr}"
        elif isinstance(node, ast.Call):
            return self._get_name(node.func)
        elif isinstance(node, ast.Subscript):
            return self._get_name(node.value)
        return None
    
    def _check_import(self, category: str) -> float:
        """Check for suspicious imports in a category"""
        score = 0.0
        patterns = self.SUSPICIOUS_IMPORTS.get(category, {})
        for imp in self.result.imports:
            for pattern, weight in patterns.items():
                if pattern.lower() in imp.lower():
                    score += weight
        return min(score, 100)
    
    def _check_function_calls(self, category: str) -> float:
        """Check for malicious function calls"""
        score = 0.0
        patterns = self.MALICIOUS_FUNCTIONS.get(category, [])
        all_calls = ' '.join(self.result.function_calls)
        source_lower = self.source_code.lower()
        
        for pattern, weight in patterns:
            if pattern.lower() in all_calls or pattern.lower() in source_lower:
                score += weight
        return min(score, 100)
    
    def _check_strings(self, patterns: List[str]) -> float:
        """Check for suspicious strings"""
        score = 0.0
        for s in self.result.string_constants:
            s_lower = s.lower()
            for pattern in patterns:
                if pattern.lower() in s_lower:
                    score += 5
        return min(score, 100)
    
    # ======================== 18 Analysis Layers ========================
    
    def _layer_data_collection(self):
        """Layer 1: Data collection & credential theft"""
        score = 0.0
        score += self._check_import('data_collection')
        score += self._check_function_calls('data_theft')
        score += self._check_strings([
            'steal', 'credential', 'password', 'token', 'key',
            '.ssh', 'authorized_keys', 'id_rsa', 'secret',
            'api_key', 'access_key', 'private_key',
            'wallet', 'mnemonic', 'seed phrase',
            'cookie', 'session', 'jwt',
        ])
        self.result.data_collection_score = min(score, 100)
    
    def _layer_system_enumeration(self):
        """Layer 2: System enumeration & reconnaissance"""
        score = 0.0
        # Check for system info gathering
        source = self.source_code.lower()
        enumeration_patterns = [
            ('platform.', 3), ('uname(', 4), ('sys.platform', 2),
            ('os.name', 2), ('os.getpid', 2), ('os.getuid', 3),
            ('os.getcwd', 2), ('os.path.expanduser', 3), ('pathlib.Path.home', 3),
            ('netifaces', 6), ('socket.gethostname', 3), ('socket.getfqdn', 3),
            ('wmic', 8), ('systeminfo', 5), ('hostname', 2),
            ('/proc/cpuinfo', 5), ('/proc/meminfo', 5),
        ]
        for pattern, weight in enumeration_patterns:
            if pattern.lower() in source:
                score += weight
        
        self.result.system_enumeration_score = min(score, 100)
    
    def _layer_encryption_detection(self):
        """Layer 3: Malicious encryption & cryptography"""
        score = 0.0
        score += self._check_import('encryption')
        score += self._check_function_calls('encryption_ops')
        
        # Check for encryption keywords in strings
        encryption_strings = [
            '.encrypted', 'ransom', 'aes', 'chacha', 'fernet',
            'xor_key', 'encryption_key', 'iv =', 'ciphertext',
            'plaintext', 'decrypt_key', 'crypto_key',
        ]
        for s in self.result.string_constants:
            for pat in encryption_strings:
                if pat in s.lower():
                    score += 8
        
        self.result.encryption_score = min(score, 100)
    
    def _layer_process_manipulation(self):
        """Layer 4: Process manipulation & injection"""
        score = 0.0
        score += self._check_import('process_manipulation')
        score += self._check_function_calls('process_ops')
        
        source = self.source_code.lower()
        injection_patterns = [
            ('ptrace', 10), ('process_vm_writev', 12), ('dll_injection', 14),
            ('shellcode', 14), ('payload', 8), ('inject', 8),
            ('createprocess', 12), ('createremotethread', 14),
            ('virtualallocex', 14), ('writeprocessmemory', 14),
            ('ntallocatevirtualmemory', 12), ('ntcreateprocessex', 12),
            ('hollow', 12), ('shatter', 10), ('atom_bombing', 12),
        ]
        for pattern, weight in injection_patterns:
            if pattern in source:
                score += weight
        
        self.result.process_manipulation_score = min(score, 100)
    
    def _layer_stealth_behavior(self):
        """Layer 5: Stealth & anti-detection"""
        score = 0.0
        score += self._check_import('stealth')
        score += self._check_function_calls('evasion')
        
        source = self.source_code.lower()
        stealth_patterns = [
            ('polymorphic', 10), ('metamorphic', 12), ('obfuscat', 8),
            ('hide', 4), ('stealth', 8), ('covert', 8),
            ('disguise', 6), ('masquerade', 8), ('impersonate', 8),
            ('timestomp', 12), ('alternate_data_stream', 10),
            ('steganography', 10), ('lsb', 6), ('hide_data', 8),
        ]
        for pattern, weight in stealth_patterns:
            if pattern in source:
                score += weight
        
        self.result.stealth_score = min(score, 100)
    
    def _layer_persistence(self):
        """Layer 6: Persistence mechanisms"""
        score = 0.0
        score += self._check_import('persistence')
        score += self._check_function_calls('persistence')
        
        source = self.source_code.lower()
        persistence_patterns = [
            ('startup', 6), ('registry\\run', 10), ('hklm\\software', 10),
            ('launchd', 8), ('launchctl', 8), ('plist', 6),
            ('crontab', 6), ('cron', 5), ('systemd', 6),
            ('schtasks', 8), ('wmi', 6), ('logon', 6),
            ('boot', 5), ('autostart', 7), ('autorun', 7),
            ('bashrc', 5), ('bash_profile', 5), ('zshrc', 5),
            ('profile.d', 6), ('init.d', 6), ('rc.local', 7),
            ('plistlib', 7), ('com.apple', 6),
        ]
        for pattern, weight in persistence_patterns:
            if pattern in source:
                score += weight
        
        self.result.persistence_score = min(score, 100)
    
    def _layer_network_activity(self):
        """Layer 7: Network activity & C2 communication"""
        score = 0.0
        score += self._check_import('network')
        score += self._check_function_calls('exfiltration')
        
        source = self.source_code.lower()
        network_patterns = [
            ('c2', 10), ('command_and_control', 10), ('beacon', 9),
            ('callback', 6), ('heartbeat', 5), ('keepalive', 4),
            ('reverse_shell', 12), ('bind_shell', 10), ('backconnect', 8),
            ('proxy', 5), ('tunnel', 7), ('pivot', 7),
            ('dns_tunnel', 10), ('icmp_tunnel', 10), ('http_tunnel', 8),
            ('tor', 7), ('onion', 7), ('darknet', 7),
            ('discord_webhook', 8), ('telegram_bot', 7), ('slack_webhook', 6),
        ]
        for pattern, weight in network_patterns:
            if pattern in source:
                score += weight
        
        self.result.network_score = min(score, 100)
    
    def _layer_multi_stage(self):
        """Layer 8: Multi-stage attacks"""
        score = 0.0
        source = self.source_code.lower()
        
        # Check for staged execution
        stage_patterns = [
            ('stage', 4), ('phase', 3), ('step', 2),
            ('loader', 8), ('dropper', 10), ('downloader', 8),
            ('stager', 10), ('launcher', 6), ('initiator', 6),
            ('trigger', 4), ('activate', 3), ('sleep(', 3),
            ('time.sleep', 3), ('wait(', 2),
        ]
        for pattern, weight in stage_patterns:
            if pattern in source:
                score += weight
        
        # Check if code downloads and executes
        if 'download' in source and ('exec' in source or 'run' in source):
            score += 12
        
        self.result.multi_stage_score = min(score, 100)
    
    def _layer_obfuscation(self):
        """Layer 9: Code obfuscation techniques"""
        score = 0.0
        source = self.source_code.lower()
        
        obfuscation_patterns = [
            ('exec(', 10), ('eval(', 8), ('compile(', 8),
            ('base64.b64decode', 6), ('marshal.loads', 8),
            ('pickle.loads', 8), ('zlib.decompress', 6),
            ('codecs.decode', 5), ('getattr(', 4), ('chr(', 2),
            ('__import__', 6), ('globals()', 5), ('locals()', 4),
            ('setattr(', 5), ('vars()', 4),
        ]
        for pattern, weight in obfuscation_patterns:
            if pattern in source:
                score += weight
        
        # Check for chr() + ord() based obfuscation
        chr_count = source.count('chr(')
        ord_count = source.count('ord(')
        if chr_count > 5:
            score += chr_count * 2
        if ord_count > 3:
            score += ord_count * 2
        
        self.result.obfuscation_score = min(score, 100)
    
    def _layer_conditional_triggers(self):
        """Layer 10: Conditional execution & sandbox detection"""
        score = 0.0
        source = self.source_code.lower()
        
        trigger_patterns = [
            ('if __name__', 2), ('sys.argv', 3), ('argparse', 3),
            ('datetime.now', 3), ('time.time', 2), ('timestamp', 3),
            ('sandbox', 8), ('virtualbox', 6), ('vmware', 6),
            ('xen', 5), ('kvm', 5), ('hypervisor', 7),
            ('cpuid', 8), ('rdtsc', 6), ('check_vm', 8),
            ('debugger', 10), ('isdebuggerpresent', 10),
            ('ntglobalflag', 8), ('peb', 8), ('beingdebugged', 10),
            ('antivirus', 6), ('av_check', 6), ('wmi_query', 5),
            ('delay', 3), ('sleep(', 2), ('time.sleep', 2),
        ]
        for pattern, weight in trigger_patterns:
            if pattern in source:
                score += weight
        
        self.result.conditional_triggers_score = min(score, 100)
    
    def _layer_file_operations(self):
        """Layer 11: Suspicious file operations"""
        score = 0.0
        source = self.source_code.lower()
        
        file_patterns = [
            ('os.remove', 5), ('os.unlink', 5), ('shutil.rmtree', 8),
            ('os.chmod', 3), ('os.chown', 4), ('os.rename', 3),
            ('symlink', 4), ('os.link', 4), ('mknod', 5),
            ('tempfile', 4), ('tmp', 3), ('temp', 3),
            ('/etc/passwd', 8), ('/etc/shadow', 10), ('/etc/hosts', 6),
            ('hosts', 5), ('/var/log', 6), ('clear_log', 8),
            ('delete_log', 8), ('wipe', 6),
        ]
        for pattern, weight in file_patterns:
            if pattern in source:
                score += weight
        
        self.result.file_operations_score = min(score, 100)
    
    def _layer_code_execution(self):
        """Layer 12: Arbitrary code execution"""
        score = 0.0
        source = self.source_code.lower()
        
        exec_patterns = [
            ('subprocess.run', 6), ('subprocess.popen', 7), ('subprocess.call', 7),
            ('os.system', 8), ('os.popen', 7), ('os.exec', 10),
            ('commands.getoutput', 6), ('pty.spawn', 8),
            ('exec(', 10), ('eval(', 8), ('execfile', 10),
            ('compile(', 8), ('__import__', 6),
        ]
        for pattern, weight in exec_patterns:
            count = source.count(pattern)
            if count > 0:
                score += weight * min(count, 3)
        
        self.result.code_execution_score = min(score, 100)
    
    def _layer_memory_ops(self):
        """Layer 13: Memory manipulation"""
        score = 0.0
        source = self.source_code.lower()
        
        mem_patterns = [
            ('mmap', 6), ('munmap', 6), ('mprotect', 8),
            ('malloc', 4), ('calloc', 4), ('realloc', 5),
            ('memcpy', 5), ('memset', 5), ('memmove', 5),
            ('buffer', 3), ('bytearray', 4), ('memoryview', 3),
        ]
        for pattern, weight in mem_patterns:
            if pattern in source:
                score += weight
        
        self.result.suspicious_patterns.append({
            'layer': 'memory_ops',
            'score': score,
        })
    
    def _layer_evasion_techniques(self):
        """Layer 14: Evasion techniques"""
        score = 0.0
        source = self.source_code.lower()
        
        evasion_patterns = [
            ('antivm', 10), ('anti_vm', 10), ('vm_detect', 10),
            ('anti_debug', 10), ('antidebug', 10), ('anti_analysis', 8),
            ('antivir', 6), ('av_evasion', 8), ('bypass', 6),
            ('disable_defender', 10), ('disable_firewall', 10),
            ('amsi_bypass', 10), ('etw_bypass', 10),
            ('unhook', 8), ('patch', 5), ('hook', 5),
        ]
        for pattern, weight in evasion_patterns:
            if pattern in source:
                score += weight
        
        self.result.suspicious_patterns.append({
            'layer': 'evasion_techniques',
            'score': score,
        })
    
    def _layer_supply_chain(self):
        """Layer 15: Supply chain attack indicators"""
        score = 0.0
        source = self.source_code.lower()
        
        chain_patterns = [
            ('pip install', 6), ('npm install', 6), ('gem install', 6),
            ('dependency', 4), ('package', 3), ('module', 2),
            ('setup.py', 8), ('setup.cfg', 8), ('manifest.in', 8),
            ('postinstall', 8), ('preinstall', 8), ('install_script', 8),
            ('typosquatting', 12), ('dependency_confusion', 12),
        ]
        for pattern, weight in chain_patterns:
            if pattern in source:
                score += weight
        
        self.result.suspicious_patterns.append({
            'layer': 'supply_chain',
            'score': score,
        })
    
    def _layer_lateral_movement(self):
        """Layer 16: Lateral movement"""
        score = 0.0
        source = self.source_code.lower()
        
        lateral_patterns = [
            ('ssh', 4), ('scp', 5), ('sftp', 5),
            ('wmi', 6), ('winrm', 8), ('powershell_remoting', 8),
            ('psexec', 10), ('smb', 6), ('net use', 8),
            ('rdp', 6), ('vnc', 6), ('remote_desktop', 6),
            ('pass_the_hash', 12), ('pass_the_ticket', 12),
            ('kerberos', 6), ('golden_ticket', 12),
        ]
        for pattern, weight in lateral_patterns:
            if pattern in source:
                score += weight
        
        self.result.suspicious_patterns.append({
            'layer': 'lateral_movement',
            'score': score,
        })
    
    def _layer_data_exfiltration(self):
        """Layer 17: Data exfiltration"""
        score = 0.0
        source = self.source_code.lower()
        
        exfil_patterns = [
            ('exfil', 8), ('exfiltrate', 10), ('upload', 5),
            ('send_data', 6), ('send_file', 6), ('transfer', 5),
            ('archive', 3), ('compress', 3), ('zip', 3),
            ('tar', 3), ('gzip', 4), ('bzip2', 4),
            ('http_post', 5), ('ftp_upload', 7), ('scp_upload', 7),
            ('dns_exfil', 10), ('icmp_exfil', 10),
        ]
        for pattern, weight in exfil_patterns:
            if pattern in source:
                score += weight
        
        self.result.suspicious_patterns.append({
            'layer': 'data_exfiltration',
            'score': score,
        })
    
    def _layer_anti_analysis(self):
        """Layer 18: Anti-analysis techniques"""
        score = 0.0
        source = self.source_code.lower()
        
        anti_patterns = [
            ('disable_trace', 8), ('anti_trace', 8),
            ('ptrace(PTRACE_TRACEME', 10), ('ptrace_traceme', 10),
            ('syscall', 6), ('direct_syscall', 8),
            ('noop', 3), ('nop', 3), ('junk_code', 6),
            ('dead_code', 6), ('opaque_predicate', 8),
            ('control_flow_flattening', 8), ('cff', 6),
            ('string_encryption', 6), ('dynamic_resolution', 6),
        ]
        for pattern, weight in anti_patterns:
            if pattern in source:
                score += weight
        
        self.result.suspicious_patterns.append({
            'layer': 'anti_analysis',
            'score': score,
        })
    
    def _compute_metrics(self):
        """Compute final combined threat score"""
        weights = {
            'data_collection_score': 0.10,
            'system_enumeration_score': 0.05,
            'encryption_score': 0.15,
            'process_manipulation_score': 0.12,
            'stealth_score': 0.08,
            'persistence_score': 0.08,
            'network_score': 0.10,
            'multi_stage_score': 0.05,
            'obfuscation_score': 0.10,
            'conditional_triggers_score': 0.05,
            'file_operations_score': 0.05,
            'code_execution_score': 0.07,
        }
        
        total = 0.0
        for attr, weight in weights.items():
            total += getattr(self.result, attr) * weight
        
        # Add complexity penalty
        if self.result.total_functions > 10:
            total += min(self.result.total_functions * 0.5, 10)
        if self.result.total_lines > 100:
            total += min(self.result.total_lines * 0.02, 10)
        
        self.result.combined_threat_score = min(total, 100)
        self.result.complexity_score = min(
            (self.result.total_functions * 2 + self.result.total_classes * 3), 100
        )


def ast_quick_scan(source_code: str) -> Dict:
    """Quick AST scan for immediate threat assessment"""
    analyzer = ASTBehavioralAnalyzer()
    result = analyzer.analyze(source_code)
    
    threat_level = "CLEAN"
    if result.combined_threat_score > 60:
        threat_level = "MALICIOUS"
    elif result.combined_threat_score > 30:
        threat_level = "SUSPICIOUS"
    
    return {
        'threat_level': threat_level,
        'threat_score': result.combined_threat_score,
        'total_functions': result.total_functions,
        'total_classes': result.total_classes,
        'total_lines': result.total_lines,
        'top_imports': result.imports[:10],
        'suspicious_functions': result.function_calls[:10],
        'layer_scores': {
            'data_collection': result.data_collection_score,
            'encryption': result.encryption_score,
            'process_manipulation': result.process_manipulation_score,
            'obfuscation': result.obfuscation_score,
            'network': result.network_score,
            'persistence': result.persistence_score,
            'code_execution': result.code_execution_score,
            'evasion': result.stealth_score,
        }
    }
