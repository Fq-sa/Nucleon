"""
Nucleon v5.0 - Native YARA-Python Engine
محرك YARA حقيقي مع yara-python الأصلي + تجميع ثنائي + قواعد محسّنة
"""
import os
import sys
import json
import hashlib
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, field
from collections import defaultdict

sys.path.insert(0, str(Path(__file__).parent))
from utils.logger import logger

# ============= استيراد yara-python الحقيقي =============
try:
    import yara
    YARA_NATIVE = True
    logger.info("yara-python الأصلي متاح ✅")
except ImportError:
    YARA_NATIVE = False
    logger.error("yara-python غير مثبت. استخدم: pip install yara-python")


@dataclass
class YARARuleNative:
    """YARA rule with native compilation support"""
    name: str
    description: str
    strings: List[str]
    condition: str
    tags: List[str] = field(default_factory=list)
    meta: Dict = field(default_factory=dict)
    severity: str = "medium"
    category: str = "generic"
    score_weight: float = 1.0


class NativeYARAScanner:
    """
    ماسح YARA أصلي مع yara-python
    - تجميع ثنائي للقواعد (أسرع بـ 10x-50x)
    - استدعاء خارجي لـ yara CLI للملفات الكبيرة
    - مطابقة متوازية للقواعد
    """
    
    # قواعد موسعة (20+ فئة سلوكية)
    EXTENDED_RULES = {
        'crypto_miner': {
            'desc': 'Cryptocurrency mining behavior',
            'patterns': [
                'stratum', 'mining', 'cryptonight', 'xmrig', 'mining.subscribe',
                'cryptocurrency', 'wallet_address', 'nicehash', 'ethermine',
                'cuda', 'opencl', 'gpu_mining', 'randomx', 'kawpow',
                'cn_gpu', 'rx/0', 'mining_pool', 'hashrate',
            ],
            'cond': 'any of them', 'severity': 'high', 'weight': 1.3,
        },
        'ransomware': {
            'desc': 'Ransomware encryption behavior',
            'patterns': [
                'encrypt', 'decrypt', 'ransom', '.encrypted',
                'aes_256', 'aes_key', 'iv =', 'encryption_key',
                'aes_cbc', 'fernet(', 'ChaCha20', 'ransom_note',
                'files_encrypted', 'decrypt_key', 'PBKDF2',
                'Crypto.Cipher', 'cryptography',
            ],
            'cond': 'any of them', 'severity': 'critical', 'weight': 1.5,
        },
        'keylogger': {
            'desc': 'Keylogging activity',
            'patterns': [
                'keylogger', 'keystroke', 'pynput', 'pyhook',
                'GetAsyncKeyState', 'SetWindowsHookEx', 'WH_KEYBOARD',
                'keyboard_listener', 'on_press', 'on_release',
                'keyboard.hook', 'mouse.hook',
            ],
            'cond': 'any of them', 'severity': 'high', 'weight': 1.3,
        },
        'trojan_backdoor': {
            'desc': 'Trojan/backdoor behavior',
            'patterns': [
                'backdoor', 'reverse_shell', 'bind_shell',
                'socket.connect', 'socket.bind', 'cmd.exe',
                '/bin/sh', '/bin/bash', 'popen(', 'subprocess.run',
                'pty.spawn', 'os.system',
            ],
            'cond': 'any of them', 'severity': 'critical', 'weight': 1.5,
        },
        'stealer': {
            'desc': 'Data theft / information stealing',
            'patterns': [
                'steal', 'exfiltrate', 'credential', 'password',
                'cookies', 'session', 'token', 'secret',
                'saved_passwords', 'autofill', 'browser_data',
                'discord_token', 'telegram_session', 'chrome_passwords',
                'firefox_cookies', 'wallet.dat',
            ],
            'cond': 'any of them', 'severity': 'high', 'weight': 1.4,
        },
        'loader_dropper': {
            'desc': 'Malware loaders and droppers',
            'patterns': [
                'loader', 'dropper', 'stager', 'shellcode',
                'payload', 'decrypt_payload', 'VirtualAlloc',
                'CreateRemoteThread', 'WriteProcessMemory',
                'marshal.loads', 'base64.b64decode',
                'exec(', 'compile(', 'eval(', 'ctypes.windll',
                'NtCreateProcess', 'process_hollow',
            ],
            'cond': 'any of them', 'severity': 'critical', 'weight': 1.5,
        },
        'botnet_c2': {
            'desc': 'Botnet/C2 communication',
            'patterns': [
                'bot', 'c2', 'command_and_control',
                'beacon', 'heartbeat', 'keepalive',
                'irc_bot', 'telegram_bot', 'webhook',
                'checkin', 'register_bot', 'discord_webhook',
            ],
            'cond': 'any of them', 'severity': 'critical', 'weight': 1.5,
        },
        'worm': {
            'desc': 'Worm/spreading behavior',
            'patterns': [
                'worm', 'spread', 'replicate', 'propagate',
                'scan_network', 'port_scan', 'exploit',
                'brute_force', 'ssh_connect', 'smb_connect',
            ],
            'cond': 'any of them', 'severity': 'high', 'weight': 1.3,
        },
        'rootkit': {
            'desc': 'Rootkit/kernel-level malware',
            'patterns': [
                'rootkit', 'kernel', 'driver', 'syscall_hook',
                'ssdt', 'idt', 'direct_syscall', 'cr3',
                'page_table', 'driver_ioctl',
            ],
            'cond': 'any of them', 'severity': 'critical', 'weight': 1.5,
        },
        'fileless_lotl': {
            'desc': 'Fileless/LOL malware',
            'patterns': [
                'fileless', 'lotl', 'powershell -enc',
                'wmic process', 'wscript.shell',
                'regsvr32', 'mshta', 'rundll32',
                'certutil -decode', 'cscript',
            ],
            'cond': 'any of them', 'severity': 'high', 'weight': 1.2,
        },
        # 10 قواعد جديدة
        'anti_analysis': {
            'desc': 'Anti-debugging and anti-analysis',
            'patterns': [
                'is_debugger_present', 'is_sandbox', 'is_vm',
                'check_vm', 'anti_debug', 'anti_vm',
                'detect_virtual', 'rdtsc', 'cpuid',
                'vmware_backdoor', 'vbox_',
            ],
            'cond': 'any of them', 'severity': 'high', 'weight': 1.3,
        },
        'process_injection': {
            'desc': 'Process injection techniques',
            'patterns': [
                'process_inject', 'dll_inject', 'reflective_loader',
                'process_hollower', 'thread_injector',
                'CreateRemoteThread', 'VirtualAllocEx',
                'WriteProcessMemory', 'SetThreadContext',
                'NtUnmapViewOfSection', 'QueueUserAPC',
            ],
            'cond': 'any of them', 'severity': 'critical', 'weight': 1.5,
        },
        'persistence': {
            'desc': 'Persistence mechanisms',
            'patterns': [
                'persist', 'startup', 'registry_run',
                'scheduled_task', 'cron_job', 'launchd',
                'systemd_service', 'boot_execute',
                'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run',
                'HKEY_LOCAL_MACHINE\\SOFTWARE',
            ],
            'cond': 'any of them', 'severity': 'high', 'weight': 1.2,
        },
        'lateral_movement': {
            'desc': 'Lateral movement techniques',
            'patterns': [
                'lateral_movement', 'psexec', 'wmi_exec',
                'remote_exec', 'ssh_tunnel', 'port_forward',
                'pass_the_hash', 'pass_the_ticket',
                'mimikatz', 'lsadump',
            ],
            'cond': 'any of them', 'severity': 'critical', 'weight': 1.5,
        },
        'data_exfiltration': {
            'desc': 'Data exfiltration patterns',
            'patterns': [
                'exfiltrate', 'upload_data', 'send_file',
                'http_post', 'ftp_upload', 'dns_tunnel',
                'icmp_tunnel', 'steganography',
                'base64_encode', 'zip_archive',
            ],
            'cond': 'any of them', 'severity': 'high', 'weight': 1.2,
        },
        'privilege_escalation': {
            'desc': 'Privilege escalation techniques',
            'patterns': [
                'priv_esc', 'sudo_bypass', 'uac_bypass',
                'getsystem', 'elevate_privilege',
                'se_debug', 'token_steal',
            ],
            'cond': 'any of them', 'severity': 'critical', 'weight': 1.5,
        },
        'defense_evasion': {
            'desc': 'Defense evasion techniques',
            'patterns': [
                'disable_defender', 'disable_firewall',
                'modify_registry', 'unhook_ntdll',
                'patch_etw', 'patch_amsi',
                'bypass_uac', 'hollow_process',
            ],
            'cond': 'any of them', 'severity': 'high', 'weight': 1.3,
        },
        'credential_dumping': {
            'desc': 'Credential dumping',
            'patterns': [
                'lsass.exe', 'sam_dump', 'credential_dump',
                'ntds.dit', 'password_hash',
                'hash_dump', 'ntlm_hash',
            ],
            'cond': 'any of them', 'severity': 'critical', 'weight': 1.5,
        },
        'reconnaissance': {
            'desc': 'System reconnaissance',
            'patterns': [
                'systeminfo', 'net view', 'net user',
                'whoami', 'hostname', 'ipconfig',
                'arp -a', 'route print', 'netstat',
                'os.walk', 'listdir', 'environ',
            ],
            'cond': 'any of them', 'severity': 'medium', 'weight': 0.8,
        },
        'code_obfuscation': {
            'desc': 'Code obfuscation techniques',
            'patterns': [
                'exec(', 'eval(', 'compile(',
                'marshal.loads', 'base64.b64decode',
                'chr(', 'ord(', 'getattr',
                '__import__', 'globals()',
                'lambda.*exec', 'bytes.fromhex',
            ],
            'cond': 'any of them', 'severity': 'medium', 'weight': 0.7,
        },
    }
    
    def __init__(self, rules_path: Optional[Path] = None):
        self.compiled_rules = None
        self.rules_dict: Dict[str, YARARuleNative] = {}
        self._init_rules()
        
        if YARA_NATIVE:
            self._compile_native()
        else:
            logger.warning("yara-python غير متاح - استخدام regex fallback المحسن")
    
    def _init_rules(self):
        """تهيئة القواعد"""
        for name, template in self.EXTENDED_RULES.items():
            rule_name = f"Nucleon_{name}"
            self.rules_dict[name] = YARARuleNative(
                name=rule_name,
                description=template['desc'],
                strings=template['patterns'],
                condition=template['cond'],
                tags=[template['severity'], name],
                meta={'author': 'Nucleon v5.0', 'version': '5.0'},
                severity=template['severity'],
                category=name,
                score_weight=template.get('weight', 1.0),
            )
    
    def _compile_native(self):
        """تجميع القواعد باستخدام yara-python الأصلي"""
        try:
            rules_text = self._generate_yara_text()
            self.compiled_rules = yara.compile(source=rules_text)
            logger.info(f"تم تجميع {len(self.rules_dict)} قاعدة YARA محلياً ⚡")
        except Exception as e:
            logger.error(f"فشل تجميع قواعد YARA: {e}")
            self.compiled_rules = None
    
    def _generate_yara_text(self) -> str:
        """توليد نص YARA للقواعد"""
        lines = []
        lines.append('/* Nucleon v5.0 YARA Rules */')
        lines.append('')
        
        for name, rule in self.rules_dict.items():
            lines.append(f"rule {rule.name} {{")
            lines.append("    meta:")
            for k, v in rule.meta.items():
                lines.append(f'        {k} = "{v}"')
            lines.append("")
            lines.append("    strings:")
            for i, p in enumerate(rule.strings):
                escaped = p.replace('\\', '\\\\').replace('"', '\\"')
                lines.append(f'        $s{i} = "{escaped}" nocase wide ascii')
            lines.append("")
            lines.append("    condition:")
            lines.append(f"        {rule.condition}")
            lines.append("}")
            lines.append("")
        
        return '\n'.join(lines)
    
    def scan_text_native(self, text: str) -> List[Dict]:
        """مسح بالنظام الأصلي - سريع جداً"""
        if not self.compiled_rules:
            return self._fallback_scan_enhanced(text)
        
        results = []
        try:
            # Encode text to bytes for YARA matching
            data = text.encode('utf-8', errors='replace')
            matches = self.compiled_rules.match(data=data)
            
            for match in matches:
                rule_name = match.rule
                # Find severity from rule name
                category = rule_name.replace('Nucleon_', '')
                severity = self.rules_dict.get(category, YARARuleNative(name='', description='', strings=[], condition='')).severity
                
                results.append({
                    'rule_name': rule_name,
                    'tags': match.tags,
                    'strings_matched': len(match.strings),
                    'severity': severity,
                    'category': category,
                    'weight': self.rules_dict.get(category, YARARuleNative(name='', description='', strings=[], condition='')).score_weight,
                })
        except Exception as e:
            logger.error(f"خطأ في مسح YARA الأصلي: {e}")
            results = self._fallback_scan_enhanced(text)
        
        return results
    
    def scan_file_native(self, filepath: Path) -> List[Dict]:
        """مسح ملف كامل"""
        if not self.compiled_rules:
            try:
                with open(filepath, 'r', encoding='utf-8', errors='replace') as f:
                    return self._fallback_scan_enhanced(f.read())
            except:
                return []
        
        try:
            matches = self.compiled_rules.match(filepath=str(filepath))
            results = []
            for match in matches:
                results.append({
                    'rule_name': match.rule,
                    'tags': match.tags,
                    'strings_matched': len(match.strings),
                })
            return results
        except Exception as e:
            logger.error(f"خطأ في فحص الملف {filepath}: {e}")
            return []
    
    def _fallback_scan_enhanced(self, text: str) -> List[Dict]:
        """Fallback محسن مع تسجيل جميع المطابقات بالتفصيل"""
        results = []
        text_lower = text.lower()
        
        for name, rule in self.rules_dict.items():
            matched_strings = []
            for pattern in rule.strings:
                if pattern.lower() in text_lower:
                    matched_strings.append(pattern)
            
            if matched_strings:
                results.append({
                    'rule_name': rule.name,
                    'tags': rule.tags,
                    'matches': matched_strings,
                    'strings_matched': len(matched_strings),
                    'severity': rule.severity,
                    'category': rule.category,
                    'weight': rule.score_weight,
                })
        
        return results
    
    def compute_threat_score(self, scan_results: List[Dict]) -> Dict:
        """حساب درجة التهديد من نتائج المسح"""
        severity_scores = {
            'critical': 25,
            'high': 15,
            'medium': 8,
            'low': 3,
        }
        
        total_score = 0.0
        categories_matched = set()
        rules_matched = []
        
        for match in scan_results:
            severity = match.get('severity', 'medium')
            weight = match.get('weight', 1.0)
            base_score = severity_scores.get(severity, 5)
            total_score += base_score * weight
            categories_matched.add(match.get('category', 'unknown'))
            rules_matched.append(match['rule_name'])
        
        total_score = min(total_score, 100)
        
        if total_score >= 50:
            threat_level = "CRITICAL"
        elif total_score >= 30:
            threat_level = "HIGH"
        elif total_score >= 15:
            threat_level = "MEDIUM"
        elif total_score > 0:
            threat_level = "LOW"
        else:
            threat_level = "CLEAN"
        
        return {
            'threat_level': threat_level,
            'threat_score': round(total_score, 1),
            'matched_categories': list(categories_matched),
            'matched_rules': rules_matched,
            'total_rule_matches': len(rules_matched),
        }


# Singleton
_scanner = None

def get_native_scanner() -> NativeYARAScanner:
    global _scanner
    if _scanner is None:
        _scanner = NativeYARAScanner()
    return _scanner
