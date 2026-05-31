import hashlib
from pathlib import Path
from typing import Dict

class HashChecker:
    def __init__(self):
        self.known_malicious = {}
        self._load_signatures()
    
    def _load_signatures(self):
        self.known_malicious = {
            "e99e16c8c8ee0e3c8b8c8e8c8e8c8e8c": "Trojan.GenericKD",
            "5d41402abc4b2a76b9719d911017c592": "Test.Signature",
        }
    
    def calculate_hash(self, file_path: Path, algorithm: str = "sha256") -> Dict[str, str]:
        try:
            hashes = {}
            for algo in ["md5", "sha1", "sha256"]:
                hasher = hashlib.new(algo)
                with open(file_path, 'rb') as f:
                    while chunk := f.read(8192):
                        hasher.update(chunk)
                hashes[algo] = hasher.hexdigest()
            return hashes
        except Exception as e:
            return {"error": str(e)}
    
    def check_signature(self, hash_value: str) -> Dict:
        for known_hash, malware_name in self.known_malicious.items():
            if hash_value.lower() == known_hash.lower():
                return {"malicious": True, "name": malware_name}
        return {"malicious": False, "name": "Clean"}
    
    def scan_file(self, file_path: Path) -> Dict:
        hashes = self.calculate_hash(file_path)
        if "error" in hashes:
            return {"status": "error", "message": hashes["error"]}
        
        md5_check = self.check_signature(hashes["md5"])
        sha256_check = self.check_signature(hashes["sha256"])
        
        is_malicious = md5_check["malicious"] or sha256_check["malicious"]
        malware_name = md5_check["name"] if md5_check["malicious"] else sha256_check["name"]
        
        return {
            "status": "malicious" if is_malicious else "clean",
            "name": malware_name,
            "hashes": hashes,
            "file": str(file_path)
        }
