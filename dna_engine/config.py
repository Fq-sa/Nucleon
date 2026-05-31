"""
Configuration for Behavioral DNA Engine
"""
from pathlib import Path

BASE_DIR = Path(__file__).parent
SAMPLES_DIR = BASE_DIR / "samples"
DATABASE_DIR = BASE_DIR / "database"
TESTS_DIR = BASE_DIR / "tests"

SAMPLES_DIR.mkdir(exist_ok=True)
DATABASE_DIR.mkdir(exist_ok=True)
TESTS_DIR.mkdir(exist_ok=True)

BEHAVIORAL_FEATURES = {
    'syscall_frequency': True,
    'timing_patterns': True,
    'memory_access': True,
    'io_operations': True,
    'network_behavior': True,
    'file_operations': True,
    'process_behavior': True,
    'context_overlay': True
}

ANALYSIS_TIMEOUT = 30
SIMILARITY_THRESHOLD = 0.75
SUSPICIOUS_THRESHOLD = 0.85
