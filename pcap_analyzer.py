"""
Nucleon v5.0 - PCAP Network Traffic Analyzer
محلل حركة الشبكة داخل الساندبوكس - رصد C2, DNS tunnels, exfiltration
"""
import os
import sys
import time
import json
import threading
import socket
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, field

sys.path.insert(0, str(Path(__file__).parent))
from utils.logger import logger

try:
    from scapy.all import sniff, AsyncSniffer, IP, TCP, UDP, DNS, Raw, Ether
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    logger.warning("scapy غير مثبت. PCAP analysis محدود.")


@dataclass
class NetworkFlow:
    """تدفق شبكة واحد"""
    src_ip: str = ""
    dst_ip: str = ""
    src_port: int = 0
    dst_port: int = 0
    protocol: str = ""
    bytes_sent: int = 0
    bytes_recv: int = 0
    packets: int = 0
    duration: float = 0.0
    
    # التحليل
    is_encrypted: bool = False
    entropy: float = 0.0
    suspicious_patterns: List[str] = field(default_factory=list)


@dataclass
class PCAPResult:
    """نتيجة تحليل الشبكة"""
    total_flows: int = 0
    total_bytes: int = 0
    unique_destinations: int = 0
    
    # تهديدات
    c2_detected: bool = False
    dns_tunnel_detected: bool = False
    data_exfil_detected: bool = False
    port_scan_detected: bool = False
    
    flows: List[NetworkFlow] = field(default_factory=list)
    threat_flags: List[str] = field(default_factory=list)
    threat_score: float = 0.0
    
    duration: float = 0.0
    error: str = ""


class PCAPAnalyzer:
    """
    محلل PCAP لحركة الشبكة
    - رصد اتصالات C2 (beaconing, heartbeat)
    - كشف DNS tunneling
    - رصد data exfiltration
    - تحليل entropy للباكيتات المشفرة
    """
    
    # أنماط C2 معروفة
    C2_PATTERNS = {
        'beacon_interval': r'(sleep|time.sleep).*\((\d+)\)',
        'heartbeat': r'(heartbeat|keepalive|ping|checkin)',
        'command_poll': r'(get_command|fetch_task|poll_server)',
        'data_post': r'(upload|send_data|report|exfiltrate)',
    }
    
    # منافذ مشبوهة
    SUSPICIOUS_PORTS = {
        4444, 1337, 31337, 5555, 6666, 6667,  # Metasploit, IRC
        8080, 8443, 9090,  # بدائل HTTP
        53,  # DNS
        3389,  # RDP
        5900, 5901,  # VNC
        22, 23,  # SSH/Telnet
    }
    
    # نطاقات IP مشبوهة
    SUSPICIOUS_CIDRS = [
        '10.', '172.16.', '192.168.',  # private
    ]
    
    def __init__(self, interface: Optional[str] = None, timeout: int = 15):
        self.interface = interface
        self.timeout = timeout
        self._sniffer: Optional[AsyncSniffer] = None
    
    def analyze_code_static(self, code: str) -> PCAPResult:
        """تحليل ثابت: تدقيق كود بايثون بحثاً عن أنماط شبكية"""
        result = PCAPResult()
        code_lower = code.lower()
        
        # Check for socket usage
        if 'socket' in code_lower:
            result.total_flows += 1
            result.threat_flags.append("SOCKET_USAGE")
        
        # Check for HTTP requests
        if 'requests.' in code or 'urllib' in code_lower:
            result.total_flows += 1
            if 'post' in code_lower and ('data' in code_lower or 'json' in code_lower):
                result.data_exfil_detected = True
                result.threat_flags.append("HTTP_DATA_POST")
        
        # Check for C2 patterns
        import re
        if 'while true' in code_lower and 'sleep' in code_lower:
            # Beaconing pattern
            sleep_matches = re.findall(r'sleep\((\d+)\)', code)
            if sleep_matches:
                sleep_time = int(sleep_matches[0])
                if sleep_time <= 60:  # frequent beacon
                    result.c2_detected = True
                    result.threat_flags.append(f"C2_BEACON_{sleep_time}s")
        
        if any(pattern in code_lower for pattern in ['heartbeat', 'beacon', 'keepalive', 'checkin']):
            result.c2_detected = True
            result.threat_flags.append("C2_COMMUNICATION")
        
        # Check for data exfiltration
        exfil_patterns = ['upload', 'send_data', 'exfiltrate', 'report_back', 'steal']
        if any(p in code_lower for p in exfil_patterns):
            result.data_exfil_detected = True
            result.threat_flags.append("DATA_EXFILTRATION")
        
        # Check for DNS tunneling
        if 'dns' in code_lower and ('tunnel' in code_lower or 'query' in code_lower):
            result.dns_tunnel_detected = True
            result.threat_flags.append("DNS_TUNNEL")
        
        # Check for suspicious ports
        for port in self.SUSPICIOUS_PORTS:
            if str(port) in code:
                result.threat_flags.append(f"SUSPICIOUS_PORT_{port}")
                result.total_flows += 1
        
        # Score
        result.threat_score = self._compute_threat_score(result)
        
        return result
    
    def capture_live(self, duration: int = 10) -> PCAPResult:
        """التقاط وتحليل حركة الشبكة الحية"""
        if not SCAPY_AVAILABLE:
            return PCAPResult(error="scapy غير متاح")
        
        result = PCAPResult()
        captured_packets = []
        
        def process_packet(pkt):
            captured_packets.append(pkt)
        
        try:
            self._sniffer = AsyncSniffer(
                iface=self.interface,
                prn=process_packet,
                store=False,
                timeout=duration,
            )
            self._sniffer.start()
            self._sniffer.join(timeout=duration + 5)
        except Exception as e:
            result.error = str(e)
            return result
        
        # Analyze captured packets
        flows = self._extract_flows(captured_packets)
        result.flows = flows
        result.total_flows = len(flows)
        result.total_bytes = sum(f.bytes_sent + f.bytes_recv for f in flows)
        
        destinations = set()
        for f in flows:
            destinations.add(f.dst_ip)
        result.unique_destinations = len(destinations)
        
        # Threat analysis
        self._analyze_threats(result, flows)
        result.threat_score = self._compute_threat_score(result)
        result.duration = duration
        
        return result
    
    def _extract_flows(self, packets: List) -> List[NetworkFlow]:
        """استخراج التدفقات من الباكيتات"""
        flows_dict = {}
        
        for pkt in packets:
            if IP not in pkt:
                continue
            
            ip_src = pkt[IP].src
            ip_dst = pkt[IP].dst
            proto = 'TCP' if TCP in pkt else 'UDP' if UDP in pkt else 'OTHER'
            
            src_port = dst_port = 0
            if TCP in pkt:
                src_port = pkt[TCP].sport
                dst_port = pkt[TCP].dport
            elif UDP in pkt:
                src_port = pkt[UDP].sport
                dst_port = pkt[UDP].dport
            
            key = f"{ip_src}:{src_port}-{ip_dst}:{dst_port}-{proto}"
            
            if key not in flows_dict:
                flows_dict[key] = NetworkFlow(
                    src_ip=ip_src, dst_ip=ip_dst,
                    src_port=src_port, dst_port=dst_port,
                    protocol=proto,
                )
            
            flow = flows_dict[key]
            pkt_len = len(pkt)
            flow.bytes_sent += pkt_len
            flow.packets += 1
        
        # Detect encrypted traffic (high entropy)
        import math
        for flow in flows_dict.values():
            if flow.protocol == 'TCP' and flow.bytes_sent > 0:
                # Simple heuristic: if average packet > 100 bytes, likely encrypted
                avg_pkt = flow.bytes_sent / max(flow.packets, 1)
                if avg_pkt > 100:
                    flow.is_encrypted = True
        
        return list(flows_dict.values())
    
    def _analyze_threats(self, result: PCAPResult, flows: List[NetworkFlow]):
        """تحليل التهديدات من التدفقات"""
        if not flows:
            return
        
        # Check for suspicious ports
        for flow in flows:
            if flow.dst_port in self.SUSPICIOUS_PORTS:
                result.threat_flags.append(f"SUSPICIOUS_DST_PORT_{flow.dst_port}")
            if flow.src_port in self.SUSPICIOUS_PORTS:
                result.threat_flags.append(f"SUSPICIOUS_SRC_PORT_{flow.src_port}")
        
        # Check for many unique destinations (scanning)
        if result.unique_destinations > 10:
            result.port_scan_detected = True
            result.threat_flags.append("PORT_SCAN_BEHAVIOR")
        
        # Check for encrypted flows to suspicious ports
        for flow in flows:
            if flow.is_encrypted and flow.dst_port in self.SUSPICIOUS_PORTS:
                result.c2_detected = True
                result.threat_flags.append("ENCRYPTED_C2")
        
        # DNS tunneling detection
        dns_flows = [f for f in flows if f.dst_port == 53]
        if dns_flows:
            for f in dns_flows:
                if f.bytes_sent > 512:  # Normal DNS < 512 bytes
                    result.dns_tunnel_detected = True
                    result.threat_flags.append("DNS_LARGE_PACKETS")
        
        # Data exfiltration (large outbound)
        for flow in flows:
            if flow.bytes_sent > 10000:  # > 10KB outbound
                result.data_exfil_detected = True
                result.threat_flags.append("LARGE_DATA_OUTBOUND")
    
    def _compute_threat_score(self, result: PCAPResult) -> float:
        """حساب درجة التهديد الشبكي"""
        score = 0.0
        
        flag_scores = {
            'C2': 25, 'DATA_EXFILTRATION': 20, 'DNS_TUNNEL': 15,
            'PORT_SCAN': 15, 'ENCRYPTED': 15, 'SUSPICIOUS_PORT': 5,
            'SOCKET_USAGE': 5,
        }
        
        for flag in result.threat_flags:
            for key, val in flag_scores.items():
                if key in flag:
                    score += val
        
        score += result.total_flows * 2
        score = min(score, 100)
        return score


def analyze_sample_network(sample_path: Path) -> PCAPResult:
    """تحليل عينة واحدة"""
    try:
        with open(sample_path, 'r', encoding='utf-8', errors='replace') as f:
            code = f.read()
    except:
        return PCAPResult(error=f"لا يمكن قراءة {sample_path}")
    
    analyzer = PCAPAnalyzer()
    return analyzer.analyze_code_static(code)
