from pathlib import Path
from typing import List, Callable, Optional
import time
from config import SUSPICIOUS_EXTENSIONS, SUSPICIOUS_PATTERNS
from core.hash_checker import HashChecker
from utils.logger import logger

class FileScanner:
    def __init__(self):
        self.hash_checker = HashChecker()
        self.results = []
    
    def scan_file(self, file_path: Path) -> dict:
        try:
            result = {
                "path": str(file_path),
                "name": file_path.name,
                "size": file_path.stat().st_size,
                "status": "clean",
                "threats": []
            }
            
            if file_path.suffix.lower() in SUSPICIOUS_EXTENSIONS:
                result["threats"].append("suspicious_extension")
            
            name_lower = file_path.name.lower()
            for pattern in SUSPICIOUS_PATTERNS:
                if pattern in name_lower:
                    result["threats"].append(f"suspicious_name:{pattern}")
            
            hash_result = self.hash_checker.scan_file(file_path)
            if hash_result["status"] == "malicious":
                result["threats"].append(f"signature:{hash_result['name']}")
            
            result["status"] = "malicious" if result["threats"] else "clean"
            result["hashes"] = hash_result.get("hashes", {})
            
            return result
        except Exception as e:
            logger.error(f"خطأ في فحص {file_path}: {e}")
            return {
                "path": str(file_path),
                "name": file_path.name,
                "status": "error",
                "threats": [],
                "error": str(e)
            }
    
    def scan_directory(self, directory: Path, progress_callback: Optional[Callable] = None, cancel_flag: Optional[Callable] = None) -> List[dict]:
        self.results = []
        
        if not directory.exists():
            return []
        
        files = [f for f in directory.rglob('*') if f.is_file()]
        total = len(files)
        
        for i, file_path in enumerate(files):
            if cancel_flag and cancel_flag():
                break
            
            result = self.scan_file(file_path)
            self.results.append(result)
            
            if result["status"] == "malicious":
                logger.warning(f"تهديد: {file_path} - {result['threats']}")
            
            if progress_callback:
                progress_callback(i + 1, total, str(file_path))
        
        return self.results
    
    def get_summary(self) -> dict:
        total = len(self.results)
        clean = sum(1 for r in self.results if r["status"] == "clean")
        malicious = sum(1 for r in self.results if r["status"] == "malicious")
        errors = sum(1 for r in self.results if r["status"] == "error")
        
        return {
            "total": total,
            "clean": clean,
            "malicious": malicious,
            "errors": errors
        }
