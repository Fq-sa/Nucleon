import os
from pathlib import Path

BASE_DIR = Path(__file__).parent
DATABASE_DIR = BASE_DIR / "database"
REPORTS_DIR = BASE_DIR / "reports"
ASSETS_DIR = BASE_DIR / "assets"

APP_NAME = "KuraTi Security"
APP_VERSION = "1.0.0"

SUSPICIOUS_EXTENSIONS = [
    ".exe", ".bat", ".cmd", ".scr", ".pif", ".vbs", ".vbe", 
    ".js", ".jse", ".wsf", ".wsh", ".ps1", ".msi", ".dll"
]

SUSPICIOUS_PATTERNS = [
    "keylog", "spy", "trojan", "malware", "virus", "hack",
    "crack", "exploit", "backdoor", "rootkit"
]

MONITORED_PORTS = [22, 23, 80, 443, 445, 3389, 8080]

HASH_DB_URL = "https://www.virustotal.com/api/v3/files"

REPORTS_DIR.mkdir(exist_ok=True)
