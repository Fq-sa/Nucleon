"""
DNA Database
قاعدة بيانات الحمض النووي - تخزن بصمات البرامج المعروفة
"""
import json
import time
from pathlib import Path
from typing import Dict, List, Optional
from .dna_fingerprint import DNAFingerprint
from .config import DATABASE_DIR
from utils.logger import logger


class DNADatabase:
    def __init__(self):
        self.db_path = DATABASE_DIR / "dna_signatures.json"
        self.signatures = {}
        self._load_database()
        
    def _load_database(self):
        if self.db_path.exists():
            try:
                with open(self.db_path, 'r') as f:
                    data = json.load(f)
                    self.signatures = data.get('signatures', {})
                    logger.info(f"تم تحميل {len(self.signatures)} بصمة من قاعدة البيانات")
            except Exception as e:
                logger.error(f"خطأ في تحميل قاعدة البيانات: {e}")
                self.signatures = {}
        else:
            self.signatures = {}
            self._save_database()
            
    def _save_database(self):
        try:
            with open(self.db_path, 'w') as f:
                json.dump({
                    'version': '1.0',
                    'last_updated': time.time(),
                    'signatures': self.signatures
                }, f, indent=2)
            logger.info(f"تم حفظ {len(self.signatures)} بصمة في قاعدة البيانات")
        except Exception as e:
            logger.error(f"خطأ في حفظ قاعدة البيانات: {e}")
            
    def add_signature(self, program_name: str, fingerprint: DNAFingerprint, is_malicious: bool = False):
        self.signatures[program_name] = {
            'fingerprint': fingerprint.to_dict(),
            'is_malicious': is_malicious,
            'added_timestamp': time.time()
        }
        self._save_database()
        logger.info(f"تمت إضافة بصمة: {program_name}")
        
    def get_signature(self, program_name: str) -> Optional[Dict]:
        return self.signatures.get(program_name)
        
    def get_all_signatures(self) -> Dict:
        return self.signatures
        
    def remove_signature(self, program_name: str):
        if program_name in self.signatures:
            del self.signatures[program_name]
            self._save_database()
            logger.info(f"تم حذف بصمة: {program_name}")
            
    def clear_database(self):
        self.signatures = {}
        self._save_database()
        logger.info("تم مسح قاعدة البيانات")
