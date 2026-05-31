"""
Behavioral DNA Fingerprinting Engine
محرك بصمة الحمض النووي السلوكية

This module implements a revolutionary approach to malware detection
by analyzing behavioral patterns instead of traditional signatures.
"""

__version__ = "1.0.0"
__author__ = "KuraTi Security Research"

from .behavior_analyzer import BehaviorAnalyzer
from .dna_fingerprint import DNAFingerprint
from .comparison_engine import ComparisonEngine
from .dna_database import DNADatabase

__all__ = [
    'BehaviorAnalyzer',
    'DNAFingerprint', 
    'ComparisonEngine',
    'DNADatabase'
]
