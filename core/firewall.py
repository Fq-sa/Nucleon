import subprocess
import platform
from typing import List, Dict
from utils.logger import logger

class Firewall:
    def __init__(self):
        self.system = platform.system().lower()
        self.blocked_ips = set()
    
    def block_ip(self, ip: str) -> Dict:
        try:
            if self.system == "linux":
                subprocess.run(
                    ["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"],
                    check=True, capture_output=True, text=True
                )
            elif self.system == "darwin":
                subprocess.run(
                    ["pfctl", "-f", f"block drop from {ip}"],
                    check=True, capture_output=True, text=True
                )
            elif self.system == "windows":
                subprocess.run(
                    ["netsh", "advfirewall", "firewall", "add", "rule", 
                     f"name=Block_{ip}", "dir=in", "action=block", 
                     f"remoteip={ip}"],
                    check=True, capture_output=True, text=True
                )
            
            self.blocked_ips.add(ip)
            logger.info(f"تم حظر IP: {ip}")
            return {"success": True, "ip": ip, "message": "تم الحظر"}
        except Exception as e:
            logger.error(f"خطأ في حظر IP {ip}: {e}")
            return {"success": False, "ip": ip, "message": str(e)}
    
    def unblock_ip(self, ip: str) -> Dict:
        try:
            if self.system == "linux":
                subprocess.run(
                    ["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"],
                    check=True, capture_output=True, text=True
                )
            elif self.system == "windows":
                subprocess.run(
                    ["netsh", "advfirewall", "firewall", "delete", "rule", 
                     f"name=Block_{ip}"],
                    check=True, capture_output=True, text=True
                )
            
            self.blocked_ips.discard(ip)
            logger.info(f"تم إلغاء حظر IP: {ip}")
            return {"success": True, "ip": ip, "message": "تم إلغاء الحظر"}
        except Exception as e:
            logger.error(f"خطأ في إلغاء حظر IP {ip}: {e}")
            return {"success": False, "ip": ip, "message": str(e)}
    
    def get_blocked_list(self) -> List[str]:
        return list(self.blocked_ips)
    
    def is_ip_blocked(self, ip: str) -> bool:
        return ip in self.blocked_ips
