"""
YARA Rules Engine v4.0
محرك قواعد YARA للكشف عن البرمجيات الخبيثة

Academic Research: ML-enhanced YARA rule generation and matching
يدعم توليد قواعد تلقائي من العينات وإنشاء قواعد سلوكية
"""

import os
import sys
import re
import json
import hashlib
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, field
from collections import defaultdict

sys.path.insert(0, str(Path(__file__).parent.parent))
from utils.logger import logger

# Try importing yara, fall back gracefully
try:
    import yara
    YARA_AVAILABLE = True
except ImportError:
    YARA_AVAILABLE = False
    logger.warning("yara-python غير مثبت. بعض الميزات غير متاحة.")


@dataclass
class YARARule:
    """YARA rule dataclass"""
    name: str
    description: str
    strings: List[str]
    condition: str
    tags: List[str] = field(default_factory=list)
    meta: Dict = field(default_factory=dict)
    severity: str = "medium"
    category: str = "generic"


class YARARuleGenerator:
    """
    Automatic YARA rule generator from malware samples
    Uses behavioral patterns and string analysis
    """
    
    # Predefined behavioral YARA rule templates
    BEHAVIORAL_RULES = {
        'crypto_miner': {
            'description': 'Detects cryptocurrency mining behavior',
            'strings': [
                'stratum', 'mining', 'cryptonight', 'xmrig',
                'mining.subscribe', 'mining.authorize',
                'cryptocurrency', 'wallet_address',
                'nicehash', 'ethermine', 'mining_pool',
                'cuda', 'opencl', 'gpu_mining',
            ],
            'condition': 'any of them',
            'severity': 'high',
            'category': 'crypto_miner',
        },
        'ransomware': {
            'description': 'Detects ransomware encryption behavior',
            'strings': [
                'encrypt', 'decrypt', 'ransom', 'bitcoin',
                '.encrypted', 'your_files', 'pay_ransom',
                'aes_256', 'aes_key', 'iv =',
                'encryption_key', 'decrypt_key',
                'files_encrypted', 'ransom_note',
                'aes_cbc', 'fernet(', 'ChaCha20',
            ],
            'condition': 'any of them',
            'severity': 'critical',
            'category': 'ransomware',
        },
        'keylogger': {
            'description': 'Detects keylogging activity',
            'strings': [
                'keylogger', 'keystroke', 'keylog',
                'on_keyboard_event', 'key_down', 'key_press',
                'pynput', 'pyhook', 'getch',
                'GetAsyncKeyState', 'SetWindowsHookEx',
                'WH_KEYBOARD', 'VK_', 'keyboard_listener',
            ],
            'condition': 'any of them',
            'severity': 'high',
            'category': 'keylogger',
        },
        'trojan': {
            'description': 'Detects trojan/backdoor behavior',
            'strings': [
                'backdoor', 'trojan', 'connect_back',
                'reverse_shell', 'bind_shell', 'shell',
                'cmd.exe', '/bin/sh', '/bin/bash',
                'socket.connect', 'socket.bind',
                'popen(', 'subprocess.run',
            ],
            'condition': 'any of them',
            'severity': 'critical',
            'category': 'trojan',
        },
        'stealer': {
            'description': 'Detects data theft / information stealing',
            'strings': [
                'steal', 'exfiltrate', 'credential', 'password',
                'cookies', 'session', 'token', 'secret',
                'saved_passwords', 'autofill', 'browser_data',
                'appdata', 'user_data', 'login_data',
                'discord_token', 'telegram_session',
            ],
            'condition': 'any of them',
            'severity': 'high',
            'category': 'stealer',
        },
        'loader': {
            'description': 'Detects malware loaders and droppers',
            'strings': [
                'loader', 'dropper', 'stager', 'inject',
                'shellcode', 'payload', 'decrypt_payload',
                'VirtualAlloc', 'CreateRemoteThread',
                'WriteProcessMemory', 'NtCreateProcess',
                'marshal.loads', 'base64.b64decode',
                'exec(', 'compile(', 'eval(',
            ],
            'condition': 'any of them',
            'severity': 'critical',
            'category': 'loader',
        },
        'botnet': {
            'description': 'Detects botnet/C2 communication patterns',
            'strings': [
                'bot', 'c2', 'command_and_control',
                'beacon', 'heartbeat', 'keepalive',
                'irc_bot', 'telegram_bot', 'discord_bot',
                'bot_token', 'webhook', 'callback',
                'checkin', 'register_bot',
            ],
            'condition': 'any of them',
            'severity': 'critical',
            'category': 'botnet',
        },
        'worm': {
            'description': 'Detects worm/spreading behavior',
            'strings': [
                'worm', 'spread', 'replicate', 'propagate',
                'scan_network', 'port_scan', 'network_scan',
                'exploit', 'brute_force', 'password_spray',
                'ssh_connect', 'smb_connect',
                'autorun.inf', 'usb_spread',
            ],
            'condition': 'any of them',
            'severity': 'high',
            'category': 'worm',
        },
        'rootkit': {
            'description': 'Detects rootkit/kernel-level malware',
            'strings': [
                'rootkit', 'kernel', 'driver', 'syscall',
                'hook', 'ssdt', 'idt', 'idt_hook',
                'ntoskrnl', 'page_table', 'cr3',
                'direct_syscall', 'sysenter',
                'driver_ioctl', 'device_control',
            ],
            'condition': 'any of them',
            'severity': 'critical',
            'category': 'rootkit',
        },
        'fileless': {
            'description': 'Detects fileless/LOTL malware',
            'strings': [
                'fileless', 'lotl', 'living_off',
                'powershell -enc', 'powershell -e ',
                'wmic process', 'wscript.shell',
                'regsvr32', 'mshta', 'rundll32',
                'cscript', 'certutil -decode',
            ],
            'condition': 'any of them',
            'severity': 'high',
            'category': 'fileless',
        },
    }
    
    def __init__(self):
        self.rules: Dict[str, YARARule] = {}
        self._init_builtin_rules()
    
    def _init_builtin_rules(self):
        """Initialize built-in behavioral YARA rules"""
        for name, template in self.BEHAVIORAL_RULES.items():
            self.rules[name] = YARARule(
                name=f"Nucleon_{name}",
                description=template['description'],
                strings=[f"${name}_{i} = \"{s}\"" for i, s in enumerate(template['strings'])],
                condition=template['condition'],
                tags=[template['category'], template['severity']],
                meta={
                    'author': 'Nucleon Research',
                    'version': '4.0.0',
                    'category': template['category'],
                    'severity': template['severity'],
                },
                severity=template['severity'],
                category=template['category'],
            )
    
    def generate_rule_from_sample(self, sample_code: str, sample_name: str) -> YARARule:
        """Generate a custom YARA rule from a malware sample"""
        strings = []
        
        # Extract unique strings from sample
        code_lower = sample_code.lower()
        
        # Find distinctive strings (length > 8 chars, not common)
        words = re.findall(r'[\'\"]([^\'\"]{10,50})[\'\"]', sample_code)
        unique_words = list(set(words))[:10]
        
        for i, word in enumerate(unique_words):
            # Escape special characters
            escaped = word.replace('\\', '\\\\').replace('"', '\\"')
            strings.append(f"$str_{i} = \"{escaped}\"")
        
        # Find hex patterns
        hex_patterns = re.findall(r'0x[0-9A-Fa-f]{4,}', sample_code)
        for i, hx in enumerate(hex_patterns[:5]):
            escaped = hx.replace('\\', '\\\\')
            strings.append(f"$hex_{i} = \"{escaped}\"")
        
        # Generate condition
        condition_parts = []
        if strings:
            str_count = len([s for s in strings if s.startswith('$str_')])
            hex_count = len([s for s in strings if s.startswith('$hex_')])
            
            if str_count > 0:
                if str_count > 3:
                    condition_parts.append(f"#{' of $str_*' if str_count > 5 else ''} >= {min(3, str_count)}")
                else:
                    condition_parts.append("any of ($str_*)")
            
            if hex_count > 0:
                condition_parts.append("any of ($hex_*)")
        
        condition = " and ".join(condition_parts) if condition_parts else "any of them"
        
        rule = YARARule(
            name=f"Nucleon_Generated_{sample_name.replace('.py', '').replace('-', '_')}",
            description=f"Auto-generated rule from sample: {sample_name}",
            strings=strings,
            condition=condition,
            tags=['auto_generated', 'machine_learning'],
            meta={
                'author': 'Nucleon Auto-Generator',
                'sample': sample_name,
                'sha256': hashlib.sha256(sample_code.encode()).hexdigest(),
            },
            severity='medium',
            category='auto_generated',
        )
        
        return rule
    
    def compile_rule(self, rule: YARARule) -> str:
        """Compile a YARA rule object to YARA rule string"""
        lines = []
        
        lines.append(f"rule {rule.name} {{")
        lines.append("    meta:")
        
        for key, value in rule.meta.items():
            if isinstance(value, str):
                lines.append(f'        {key} = "{value}"')
            else:
                lines.append(f'        {key} = {value}')
        
        lines.append("")
        lines.append("    strings:")
        for s in rule.strings:
            lines.append(f"        {s}")
        
        lines.append("")
        lines.append("    condition:")
        lines.append(f"        {rule.condition}")
        lines.append("}")
        
        return "\n".join(lines)
    
    def compile_all_rules(self) -> str:
        """Compile all rules to a single YARA rules file"""
        all_rules = []
        
        rules_header = """/*
 * Nucleon Behavioral YARA Rules v4.0
 * Auto-generated by Nucleon Research
 * 
 * These rules are for academic research and educational purposes only.
 * Do not use for malicious activities.
 */

"""
        all_rules.append(rules_header)
        
        for rule in self.rules.values():
            all_rules.append(self.compile_rule(rule))
            all_rules.append("")
        
        return "\n".join(all_rules)
    
    def save_rules(self, output_path: Path):
        """Save compiled YARA rules to file"""
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, 'w') as f:
            f.write(self.compile_all_rules())
        logger.info(f"تم حفظ قواعد YARA: {output_path}")


class YARAScanner:
    """
    YARA-based malware scanner
    Uses compiled YARA rules for fast pattern matching
    """
    
    def __init__(self, rules_dir: Optional[Path] = None):
        self.generator = YARARuleGenerator()
        self.compiled_rules = None
        self._compile_rules()
    
    def _compile_rules(self):
        """Compile all rules for fast scanning"""
        if not YARA_AVAILABLE:
            self.compiled_rules = None
            return
        
        try:
            rules_text = self.generator.compile_all_rules()
            self.compiled_rules = yara.compile(source=rules_text)
            logger.info(f"تم تجميع قواعد YARA ({len(self.generator.rules)} قاعدة)")
        except Exception as e:
            logger.error(f"خطأ في تجميع قواعد YARA: {e}")
            self.compiled_rules = None
    
    def scan_text(self, text: str) -> List[Dict]:
        """Scan text content with YARA rules"""
        if not self.compiled_rules:
            return self._fallback_scan(text)
        
        results = []
        try:
            matches = self.compiled_rules.match(data=text)
            for match in matches:
                results.append({
                    'rule_name': match.rule,
                    'namespace': match.namespace,
                    'tags': match.tags,
                    'matches': [{
                        'offset': m[0],
                        'string_id': m[1],
                        'data': m[2].decode('utf-8', errors='replace'),
                    } for m in match.strings],
                })
        except Exception as e:
            logger.error(f"خطأ في مسح YARA: {e}")
            results = self._fallback_scan(text)
        
        return results
    
    def scan_file(self, filepath: Path) -> List[Dict]:
        """Scan a file with YARA rules"""
        try:
            with open(filepath, 'rb') as f:
                data = f.read()
            
            if not self.compiled_rules:
                return self._fallback_scan(data.decode('utf-8', errors='replace'))
            
            matches = self.compiled_rules.match(data=data)
            results = []
            for match in matches:
                results.append({
                    'rule_name': match.rule,
                    'tags': match.tags,
                    'matches_count': len(match.strings),
                })
            return results
        except Exception as e:
            logger.error(f"خطأ في فحص الملف {filepath}: {e}")
            return []
    
    def _fallback_scan(self, text: str) -> List[Dict]:
        """Fallback scan using regex when yara-python is not available"""
        results = []
        text_lower = text.lower() if isinstance(text, str) else text.decode('utf-8', errors='replace').lower()
        
        for rule_name, template in self.generator.BEHAVIORAL_RULES.items():
            matches = []
            for pattern in template['strings']:
                if pattern.lower() in text_lower:
                    matches.append(pattern)
            
            if matches:
                results.append({
                    'rule_name': f"Nucleon_{rule_name}",
                    'tags': [template['category'], template['severity']],
                    'matches': matches,
                    'severity': template['severity'],
                    'category': template['category'],
                })
        
        return results
    
    def scan_with_ml(self, text: str) -> Dict:
        """
        Enhanced scan with ML-based scoring
        Returns detailed threat assessment
        """
        yara_matches = self.scan_text(text)
        
        # Compute threat score from YARA matches
        severity_weights = {
            'critical': 25,
            'high': 15,
            'medium': 8,
            'low': 3,
        }
        
        total_score = 0
        matched_categories = set()
        matched_rules = []
        
        for match in yara_matches:
            severity = match.get('severity', 'medium')
            category = match.get('category', 'unknown')
            
            total_score += severity_weights.get(severity, 5)
            matched_categories.add(category)
            matched_rules.append(match['rule_name'])
        
        # Determine threat level
        if total_score >= 40:
            threat_level = "CRITICAL"
        elif total_score >= 25:
            threat_level = "HIGH"
        elif total_score >= 10:
            threat_level = "MEDIUM"
        elif total_score > 0:
            threat_level = "LOW"
        else:
            threat_level = "CLEAN"
        
        return {
            'threat_level': threat_level,
            'threat_score': min(total_score, 100),
            'matched_categories': list(matched_categories),
            'matched_rules': matched_rules,
            'total_matches': len(yara_matches),
            'yara_results': yara_matches,
        }


# Pre-built YARA rules directory
def generate_default_ruleset(output_path: Path) -> Path:
    """Generate and save default YARA ruleset"""
    generator = YARARuleGenerator()
    output_file = output_path / "nucleon_rules.yar"
    generator.save_rules(output_file)
    return output_file


# Singleton scanner instance
_scanner_instance = None

def get_scanner() -> YARAScanner:
    """Get or create singleton YARA scanner"""
    global _scanner_instance
    if _scanner_instance is None:
        _scanner_instance = YARAScanner()
    return _scanner_instance
