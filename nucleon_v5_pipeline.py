"""
Nucleon v5.0 - Unified Detection Pipeline
خط أنابيب موحّد يجمع كل المحركات السبعة وينتج تقريراً شاملاً
"""
import os
import sys
import json
import time
import argparse
from pathlib import Path
from typing import Dict, List, Optional
from dataclasses import dataclass, field, asdict

sys.path.insert(0, str(Path(__file__).parent))

from utils.logger import logger

# استيراد كل المحركات
from integrated_sandbox import IntegratedSandboxEngine, IntegratedResult
from yara_engine.native_yara_scanner import NativeYARAScanner, get_native_scanner
from xgboost_classifier import XGBoostEnsembleClassifier, EnsembledSample, get_classifier
from pcap_analyzer import PCAPAnalyzer, analyze_sample_network
from memory_forensics import MemoryForensicsEngine, analyze_sample_memory
from dynamic_thresholds import DynamicThresholdTuner, get_tuner
from binary_analysis.cross_platform_binary import BinaryAnalyzer, analyze_binary_file


@dataclass
class UnifiedResult:
    """نتيجة موحدة من كل المحركات"""
    sample_name: str = ""
    sample_path: str = ""
    
    # 7 engine scores
    ast_score: float = 0.0
    yara_score: float = 0.0
    runtime_score: float = 0.0
    sandbox_score: float = 0.0
    pcap_score: float = 0.0
    memory_score: float = 0.0
    binary_score: float = 0.0
    
    # Combined
    combined_score: float = 0.0
    xgboost_confidence: float = 0.0
    verdict: str = "CLEAN"
    
    # Flags
    threat_flags: List[str] = field(default_factory=list)
    engine_alerts: Dict[str, List[str]] = field(default_factory=dict)
    
    # Performance
    duration: float = 0.0


class NucleonV5Pipeline:
    """
    خط أنابيب Nucleon v5.0 الموحد
    يشمل المحركات السبعة + XGBoost + عتبات ديناميكية
    """
    
    def __init__(self, mode: str = 'max_f1', timeout: int = 15):
        self.mode = mode
        self.timeout = timeout
        
        # Initialize all engines
        logger.info("تهيئة المحركات...")
        self.yara_scanner = get_native_scanner()
        self.xgb_classifier = get_classifier()
        
        # Load trained model if exists
        model_path = Path(__file__).parent / "reports" / "xgboost_ensemble_model.json"
        if model_path.exists():
            self.xgb_classifier.load_model(model_path)
            logger.info(f"تم تحميل نموذج XGBoost المدرب ✅")
        
        self.threshold_tuner = get_tuner(mode=mode)
        self.pcap_analyzer = PCAPAnalyzer(timeout=timeout)
        self.memory_engine = MemoryForensicsEngine()
        self.binary_analyzer = BinaryAnalyzer()
        self.integrated_engine = IntegratedSandboxEngine(timeout=timeout)
        
        self.results: List[UnifiedResult] = []
        logger.info(f"تم تهيئة {7} محركات ✅")
    
    def analyze_sample(self, sample_path: Path) -> UnifiedResult:
        """تحليل عينة واحدة بكل المحركات"""
        result = UnifiedResult(
            sample_name=sample_path.name,
            sample_path=str(sample_path),
        )
        
        start = time.time()
        engine_alerts = {}
        
        # Read source
        try:
            with open(sample_path, 'r', encoding='utf-8', errors='replace') as f:
                code = f.read()
        except:
            code = ""
        
        # 1. AST Static Analysis (via integrated engine)
        try:
            integrated = self.integrated_engine.analyze_sample(sample_path)
            result.ast_score = integrated.static_score
            result.sandbox_score = integrated.sandbox_score
            if integrated.threat_flags:
                engine_alerts['ast_sandbox'] = integrated.threat_flags
        except Exception as e:
            logger.warning(f"فشل AST/Sandbox لـ {sample_path.name}: {e}")
        
        # 2. YARA Native Scan
        try:
            yara_results = self.yara_scanner.scan_text_native(code)
            yara_threat = self.yara_scanner.compute_threat_score(yara_results)
            result.yara_score = yara_threat['threat_score']
            if yara_threat['matched_rules']:
                engine_alerts['yara'] = yara_threat['matched_rules']
        except Exception as e:
            logger.warning(f"فشل YARA لـ {sample_path.name}: {e}")
        
        # 3. PCAP Network Analysis
        try:
            pcap_result = self.pcap_analyzer.analyze_code_static(code)
            result.pcap_score = pcap_result.threat_score
            if pcap_result.threat_flags:
                engine_alerts['pcap'] = pcap_result.threat_flags
        except Exception as e:
            logger.warning(f"فشل PCAP لـ {sample_path.name}: {e}")
        
        # 4. Memory Forensics
        try:
            mem_result = self.memory_engine.analyze_code_static(code)
            result.memory_score = mem_result.threat_score
            if mem_result.threat_flags:
                engine_alerts['memory'] = mem_result.threat_flags
        except Exception as e:
            logger.warning(f"فشل Memory لـ {sample_path.name}: {e}")
        
        # 5. Binary Analysis (if applicable)
        try:
            if sample_path.suffix in ['.exe', '.dll', '.so', '.dylib', '.bin', '.elf']:
                bin_result = self.binary_analyzer.analyze_file(sample_path)
                result.binary_score = bin_result.threat_score
                if bin_result.threat_flags:
                    engine_alerts['binary'] = bin_result.threat_flags
        except Exception as e:
            logger.warning(f"فشل Binary لـ {sample_path.name}: {e}")
        
        # Runtime score = sandbox integration already covered in step 1
        result.runtime_score = integrated.duration if 'integrated' in dir() and hasattr(integrated, 'duration') else 0
        
        # Store alerts
        result.engine_alerts = engine_alerts
        
        # Combine all flags
        all_flags = []
        for alerts in engine_alerts.values():
            all_flags.extend(alerts)
        result.threat_flags = all_flags
        
        # XGBoost ensemble classification
        ensemble_sample = EnsembledSample(
            name=result.sample_name,
            ast_score=result.ast_score,
            yara_score=result.yara_score,
            runtime_score=result.runtime_score,
            sandbox_score=result.sandbox_score,
            pcap_score=result.pcap_score,
            memory_score=result.memory_score,
            binary_score=result.binary_score,
        )
        
        pred, confidence = self.xgb_classifier.predict(ensemble_sample)
        result.xgboost_confidence = confidence
        
        # Dynamic threshold combined score
        engine_scores = {
            'ast': result.ast_score,
            'yara': result.yara_score,
            'runtime': result.runtime_score,
            'sandbox': result.sandbox_score,
            'pcap': result.pcap_score,
            'memory': result.memory_score,
            'binary': result.binary_score,
        }
        
        combined, dynamic_verdict = self.threshold_tuner.compute_combined_threshold(engine_scores)
        result.combined_score = combined
        
        # Final verdict: majority vote (XGBoost + Dynamic Thresholds)
        if result.xgboost_confidence > 0.5 and combined >= 35:
            result.verdict = "MALICIOUS"
        elif result.xgboost_confidence > 0.3 or combined >= 22:
            result.verdict = "SUSPICIOUS"
        else:
            result.verdict = "CLEAN"
        
        result.duration = time.time() - start
        return result
    
    def analyze_directory(self, samples_dir: Path, file_pattern: str = "*.py") -> List[UnifiedResult]:
        """تحليل كل العينات في مجلد"""
        samples = sorted(samples_dir.glob(file_pattern))
        
        # Filter: skip __init__ and helpers
        samples = [s for s in samples if not any(
            x in s.name for x in ['__init__', 'config', 'setup', 'logger', '__pycache__']
        )]
        
        logger.info(f"بدء تحليل {len(samples)} عينة بكل المحركات...")
        
        for i, sample in enumerate(samples, 1):
            logger.info(f"[{i}/{len(samples)}] {sample.name}")
            try:
                result = self.analyze_sample(sample)
                self.results.append(result)
            except Exception as e:
                logger.error(f"فشل تحليل {sample.name}: {e}")
        
        return self.results
    
    def compute_statistics(self) -> Dict:
        """إحصائيات شاملة"""
        if not self.results:
            return {}
        
        total = len(self.results)
        malicious = sum(1 for r in self.results if r.verdict == "MALICIOUS")
        suspicious = sum(1 for r in self.results if r.verdict == "SUSPICIOUS")
        clean = sum(1 for r in self.results if r.verdict == "CLEAN")
        
        # إذا كنا نعرف labels (مثلاً من أسماء الملفات)
        # "zen" أو "mal" أو "trojan" في الاسم = خبيث
        # "clean" في الاسم = نظيف
        known_malware = sum(1 for r in self.results if any(
            x in r.sample_name.lower() for x in [
                'zen', 'mal', 'trojan', 'ransom', 'keylog', 'steal',
                'inject', 'backdoor', 'worm', 'bot', 'rootkit',
                'loader', 'dropper', 'crypt', 'obfuscat',
            ]
        ))
        known_clean = sum(1 for r in self.results if 'clean' in r.sample_name.lower())
        
        engine_avg = {
            'ast': sum(r.ast_score for r in self.results) / total,
            'yara': sum(r.yara_score for r in self.results) / total,
            'pcap': sum(r.pcap_score for r in self.results) / total,
            'memory': sum(r.memory_score for r in self.results) / total,
        }
        
        return {
            'engine': 'Nucleon v5.0 - 7 Engines + XGBoost + Dynamic Thresholds',
            'mode': self.mode,
            'total_samples': total,
            'malicious': malicious,
            'suspicious': suspicious,
            'clean': clean,
            'detection_rate': round((malicious + suspicious) / total * 100, 1),
            'known_malware_in_dataset': known_malware,
            'known_clean_in_dataset': known_clean,
            'engine_averages': {k: round(v, 1) for k, v in engine_avg.items()},
            'avg_combined_score': round(sum(r.combined_score for r in self.results) / total, 1),
            'avg_xgboost_confidence': round(sum(r.xgboost_confidence for r in self.results) / total, 2),
        }
    
    def generate_report(self, output_path: Path) -> Dict:
        """توليد تقرير JSON كامل"""
        stats = self.compute_statistics()
        
        report = {
            'stats': stats,
            'timestamp': time.time(),
            'thresholds': {},
            'samples': [],
        }
        
        # Save threshold configs
        for engine, cfg in self.threshold_tuner.thresholds.items():
            report['thresholds'][engine] = {
                'malicious_threshold': cfg.malicious_threshold,
                'suspicious_threshold': cfg.suspicious_threshold,
                'weight': cfg.weight,
            }
        
        for r in self.results:
            report['samples'].append({
                'name': r.sample_name,
                'verdict': r.verdict,
                'combined_score': round(r.combined_score, 1),
                'xgboost_confidence': round(r.xgboost_confidence, 2),
                'scores': {
                    'ast': round(r.ast_score, 1),
                    'yara': round(r.yara_score, 1),
                    'runtime': round(r.runtime_score, 1),
                    'sandbox': round(r.sandbox_score, 1),
                    'pcap': round(r.pcap_score, 1),
                    'memory': round(r.memory_score, 1),
                    'binary': round(r.binary_score, 1),
                },
                'threat_flags': r.threat_flags[:10],  # Top 10
                'engine_alerts': r.engine_alerts,
                'duration': round(r.duration, 2),
            })
        
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        
        logger.info(f"تم حفظ التقرير: {output_path}")
        return report


def main():
    parser = argparse.ArgumentParser(description="Nucleon v5.0 - Unified Detection Pipeline")
    parser.add_argument('--samples-dir', type=str, default=None,
                        help='مجلد العينات (افتراضي: dna_engine/samples)')
    parser.add_argument('--output', type=str, default=None,
                        help='مسار التقرير (افتراضي: reports/nucleon_v5_report.json)')
    parser.add_argument('--mode', choices=['max_f1', 'zero_fp', 'max_recall', 'balanced'],
                        default='max_f1', help='نمط المعايرة')
    parser.add_argument('--timeout', type=int, default=15, help='مهلة الساندبوكس')
    
    args = parser.parse_args()
    
    project_root = Path(__file__).parent
    samples_dir = Path(args.samples_dir) if args.samples_dir else project_root / "dna_engine" / "samples"
    output_path = Path(args.output) if args.output else project_root / "reports" / "nucleon_v5_report.json"
    
    print("\n" + "=" * 70)
    print("  🧬  Nucleon v5.0 - Unified Behavioral DNA Pipeline")
    print("  7 Engines · XGBoost Ensemble · Dynamic Thresholds")
    print("=" * 70)
    
    print(f"\n  Mode: {args.mode}")
    print(f"  Samples: {samples_dir}")
    print(f"  Report: {output_path}")
    
    # Run pipeline
    pipeline = NucleonV5Pipeline(mode=args.mode, timeout=args.timeout)
    pipeline.analyze_directory(samples_dir)
    
    # Generate report
    report = pipeline.generate_report(output_path)
    stats = report['stats']
    
    # Print results
    print(f"\n{'─' * 70}")
    print(f"  Results")
    print(f"{'─' * 70}")
    print(f"  Total: {stats['total_samples']} samples")
    print(f"  MALICIOUS:  {stats['malicious']}")
    print(f"  SUSPICIOUS: {stats['suspicious']}")
    print(f"  CLEAN:      {stats['clean']}")
    print(f"  Detection:  {stats['detection_rate']}%")
    print(f"  Avg Score:  {stats['avg_combined_score']}")
    print(f"  Avg XGBoost: {stats['avg_xgboost_confidence']}")
    
    print(f"\n{'─' * 70}")
    print(f"  Engine Averages")
    print(f"{'─' * 70}")
    for engine, avg in stats.get('engine_averages', {}).items():
        bar = '█' * int(avg / 5) + '░' * (20 - int(avg / 5))
        print(f"  {engine:<8}: {avg:>5.1f} {bar}")
    
    print(f"\n{'─' * 70}")
    print(f"  Thresholds (Dynamic - {args.mode})")
    print(f"{'─' * 70}")
    for engine, cfg in report.get('thresholds', {}).items():
        print(f"  {engine:<8}: mal={cfg['malicious_threshold']:.0f} sus={cfg['suspicious_threshold']:.0f} w={cfg['weight']:.1f}")
    
    print(f"\n  ✓ Report saved: {output_path}")
    print("=" * 70)
    print()


if __name__ == "__main__":
    main()
