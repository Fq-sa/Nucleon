import psutil
import socket
from typing import List, Dict
from utils.logger import logger
from config import MONITORED_PORTS

class NetworkMonitor:
    def __init__(self):
        self.connections = []
        self.suspicious_ports = MONITORED_PORTS
    
    def get_connections(self) -> List[Dict]:
        try:
            connections = psutil.net_connections(kind='inet')
            result = []
            
            for conn in connections:
                try:
                    process = psutil.Process(conn.pid) if conn.pid else None
                    process_name = process.name() if process else "Unknown"
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    process_name = "Unknown"
                
                conn_info = {
                    "local_address": f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else "",
                    "remote_address": f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else "",
                    "status": conn.status,
                    "type": "TCP" if conn.type == socket.SOCK_STREAM else "UDP",
                    "pid": conn.pid,
                    "process": process_name,
                    "suspicious": False
                }
                
                if conn.raddr and conn.raddr.port in self.suspicious_ports:
                    conn_info["suspicious"] = True
                    conn_info["reason"] = f"منفذ مشبوه: {conn.raddr.port}"
                
                if conn.status == "ESTABLISHED" and conn.raddr:
                    try:
                        hostname = socket.gethostbyaddr(conn.raddr.ip)[0]
                        conn_info["hostname"] = hostname
                    except (socket.herror, socket.gaierror):
                        pass
                
                result.append(conn_info)
            
            self.connections = result
            return result
        except Exception as e:
            logger.error(f"خطأ في مراقبة الشبكة: {e}")
            return []
    
    def get_stats(self) -> Dict:
        try:
            io = psutil.net_io_counters()
            return {
                "bytes_sent": io.bytes_sent,
                "bytes_recv": io.bytes_recv,
                "packets_sent": io.packets_sent,
                "packets_recv": io.packets_recv,
                "errors_in": io.errin,
                "errors_out": io.errout
            }
        except Exception as e:
            logger.error(f"خطأ في إحصائيات الشبكة: {e}")
            return {}
    
    def get_suspicious_connections(self) -> List[Dict]:
        return [c for c in self.connections if c.get("suspicious")]
