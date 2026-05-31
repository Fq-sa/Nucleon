import psutil
from typing import List, Dict
from config import SUSPICIOUS_PATTERNS
from utils.logger import logger

class ProcessScanner:
    def __init__(self):
        self.processes = []
    
    def get_processes(self) -> List[Dict]:
        try:
            result = []
            
            for proc in psutil.process_iter(['pid', 'name', 'username', 'cpu_percent', 'memory_percent', 'status', 'create_time']):
                try:
                    info = proc.info
                    process = {
                        "pid": info['pid'],
                        "name": info['name'],
                        "username": info['username'],
                        "cpu": info['cpu_percent'] or 0.0,
                        "memory": info['memory_percent'] or 0.0,
                        "status": info['status'],
                        "suspicious": False,
                        "reasons": []
                    }
                    
                    name_lower = info['name'].lower()
                    for pattern in SUSPICIOUS_PATTERNS:
                        if pattern in name_lower:
                            process["suspicious"] = True
                            process["reasons"].append(f"اسم مشبوه: {pattern}")
                    
                    if process['cpu'] > 80:
                        process["suspicious"] = True
                        process["reasons"].append(f"استهلاك عالي للمعالج: {process['cpu']:.1f}%")
                    
                    if process['memory'] > 50:
                        process["suspicious"] = True
                        process["reasons"].append(f"استهلاك عالي للذاكرة: {process['memory']:.1f}%")
                    
                    result.append(process)
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    continue
            
            self.processes = result
            return result
        except Exception as e:
            logger.error(f"خطأ في فحص العمليات: {e}")
            return []
    
    def get_suspicious_processes(self) -> List[Dict]:
        return [p for p in self.processes if p.get("suspicious")]
    
    def kill_process(self, pid: int) -> Dict:
        try:
            proc = psutil.Process(pid)
            proc.kill()
            logger.info(f"تم إنهاء العملية: {pid}")
            return {"success": True, "pid": pid, "message": "تم الإنهاء"}
        except Exception as e:
            logger.error(f"خطأ في إنهاء العملية {pid}: {e}")
            return {"success": False, "pid": pid, "message": str(e)}
