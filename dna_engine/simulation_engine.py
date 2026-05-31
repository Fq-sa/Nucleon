"""
Simulation Engine
محرك المحاكاة والفحص - يشغل البرامج ويحلل سلوكها
"""
import subprocess
import time
from pathlib import Path
from typing import Dict, List, Optional
from .behavior_analyzer import BehaviorAnalyzer
from .dna_fingerprint import DNAEngine, DNAFingerprint
from .comparison_engine import ComparisonEngine
from .dna_database import DNADatabase
from utils.logger import logger


class SimulationEngine:
    def __init__(self):
        self.dna_engine = DNAEngine()
        self.comparison_engine = ComparisonEngine()
        self.database = DNADatabase()
        
    def analyze_program(self, process: subprocess.Popen, program_name: str, 
                       duration: int = 10) -> Dict:
        """تحليل برنامج واستخراج بصمته السلوكية"""
        logger.info(f"بدء تحليل البرنامج: {program_name} (PID: {process.pid})")
        
        analyzer = BehaviorAnalyzer(process.pid, timeout=duration)
        analyzer.start_monitoring()
        
        try:
            process.wait(timeout=duration + 5)
        except subprocess.TimeoutExpired:
            logger.warning(f"البرنامج {program_name} تجاوز الوقت المحدد")
            process.terminate()
            
        analyzer.stop_monitoring()
        
        behavioral_data = analyzer.get_behavioral_data()
        fingerprint = self.dna_engine.generate_fingerprint(behavioral_data)
        
        result = {
            'program_name': program_name,
            'pid': process.pid,
            'fingerprint': fingerprint,
            'behavioral_data': behavioral_data,
            'analysis_duration': duration,
            'status': 'completed'
        }
        
        logger.info(f"اكتمل تحليل {program_name}")
        return result
        
    def compare_with_database(self, fingerprint: DNAFingerprint, 
                             program_name: str) -> Dict:
        """مقارنة بصمة مع قاعدة البيانات باستخدام نظام التصويت المرجح"""
        logger.info(f"مقارنة بصمة {program_name} مع قاعدة البيانات")
        
        all_signatures = self.database.get_all_signatures()
        results = []
        
        for sig_name, sig_data in all_signatures.items():
            if sig_name == program_name:
                continue
                
            sig_fingerprint = DNAFingerprint(**sig_data['fingerprint'])
            similarity_result = self.comparison_engine.calculate_similarity(
                fingerprint, sig_fingerprint
            )
            
            results.append({
                'compared_with': sig_name,
                'is_known_malicious': sig_data['is_malicious'],
                'similarity': similarity_result['overall_similarity'],
                'match': similarity_result['match'],
                'suspicious': similarity_result['suspicious'],
                'details': similarity_result
            })
        
        results.sort(key=lambda x: x['similarity'], reverse=True)
        
        best_match = results[0] if results else None
        
        # Aggregate scoring: separate malware and clean similarities
        malware_sims = [r['similarity'] for r in results if r['is_known_malicious']]
        clean_sims = [r['similarity'] for r in results if not r['is_known_malicious']]
        
        # Calculate aggregate scores
        malware_score = 0.0
        clean_score = 0.0
        
        if malware_sims:
            # Weighted average: higher similarities matter more
            malware_sims_sorted = sorted(malware_sims, reverse=True)
            weights = [1.0 / (i + 1) for i in range(len(malware_sims_sorted))]
            malware_score = sum(s * w for s, w in zip(malware_sims_sorted, weights)) / sum(weights)
        
        if clean_sims:
            clean_sims_sorted = sorted(clean_sims, reverse=True)
            weights = [1.0 / (i + 1) for i in range(len(clean_sims_sorted))]
            clean_score = sum(s * w for s, w in zip(clean_sims_sorted, weights)) / sum(weights)
        
        # Calculate maliciousness index (how much more like malware than clean)
        if malware_sims or clean_sims:
            max_malware = max(malware_sims) if malware_sims else 0.0
            max_clean = max(clean_sims) if clean_sims else 0.0
            
            # Maliciousness index: positive = more like malware, negative = more like clean
            mal_index = malware_score - clean_score
            
            # Count high-similarity malware matches
            high_sim_malware_count = sum(1 for s in malware_sims if s > 0.7)
        else:
            mal_index = 0.0
            high_sim_malware_count = 0
            max_malware = 0.0
            max_clean = 0.0
        
        # Verdict based on aggregate scoring
        verdict = 'clean'
        if len(results) > 0:
            # Malicious: strong aggregate malware similarity OR very high individual match
            if mal_index > 0.05 and high_sim_malware_count >= 1:
                verdict = 'malicious'
            elif max_malware > 0.85 and malware_score > clean_score:
                verdict = 'malicious'
            elif mal_index > 0.0 or high_sim_malware_count >= 1:
                verdict = 'suspicious'
            elif max_malware > 0.7 and malware_score > 0.5:
                verdict = 'suspicious'
        
        return {
            'program_name': program_name,
            'verdict': verdict,
            'best_match': best_match,
            'all_comparisons': results,
            'aggregate_scores': {
                'malware_score': malware_score,
                'clean_score': clean_score,
                'maliciousness_index': mal_index,
                'high_sim_malware_count': high_sim_malware_count,
                'max_malware_similarity': max_malware,
                'max_clean_similarity': max_clean
            }
        }
        
    def run_full_analysis(self, sample_runner: callable, program_name: str, 
                         duration: int = 10, is_malicious: bool = False) -> Dict:
        """تشغيل تحليل كامل لبرنامج"""
        logger.info(f"بدء التحليل الكامل لـ {program_name}")
        
        process = sample_runner(duration)
        
        analysis_result = self.analyze_program(process, program_name, duration)
        fingerprint = analysis_result['fingerprint']
        
        self.database.add_signature(program_name, fingerprint, is_malicious)
        
        comparison_result = self.compare_with_database(fingerprint, program_name)
        
        full_result = {
            'program_name': program_name,
            'is_known_malicious': is_malicious,
            'analysis': analysis_result,
            'comparison': comparison_result,
            'timestamp': time.time()
        }
        
        logger.info(f"اكتمل التحليل الكامل لـ {program_name}: {comparison_result['verdict']}")
        return full_result
