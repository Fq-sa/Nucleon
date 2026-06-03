"""
Nucleon v5.0 - Integrated Sandbox Runtime Engine
يدمج الساندبوكس مع التحليل السلوكي ويغذي النتائج لباقي المحركات
"""
import os
import sys
import time
import json
import subprocess
import tempfile
from pathlib import Path
from typing import Dict, List, Optional
from dataclasses import dataclass, field

sys.path.insert(0, str(Path(__file__).parent))
from sandbox.sandbox_runner import SandboxRunner, SandboxConfig, SandboxResult
from dna_engine.runtime_engine import RuntimeMonitor, enhanced_static_analysis
from utils.logger import logger


@dataclass
class IntegratedResult:
    """نتيجة متكاملة: static + sandbox runtime + DNA fingerprint"""
    sample_name: str = ""
    sample_path: str = ""
    
    # AST/Static
    static_score: float = 0.0
    static_features: Dict = field(default_factory=dict)
    
    # Sandbox Runtime
    sandbox_result: Optional[SandboxResult] = None
    sandbox_score: float = 0.0
    sandbox_anomalies: List[str] = field(default_factory=list)
    
    # Combined
    combined_score: float = 0.0
    verdict: str = "CLEAN"
    threat_flags: List[str] = field(default_factory=list)
    
    # Timing
    duration: float = 0.0


class IntegratedSandboxEngine:
    """
    المحرك المتكامل: يشغل العينة في الساندبوكس + يحلل static + يدمج النتائج
    """
    
    def __init__(self, timeout: int = 15, network_enabled: bool = False):
        self.timeout = timeout
        self.network_enabled = network_enabled
        self.results: List[IntegratedResult] = []
    
    def analyze_sample(self, sample_path: Path) -> IntegratedResult:
        """تحليل عينة واحدة: static + sandbox runtime"""
        result = IntegratedResult()
        result.sample_name = sample_path.name
        result.sample_path = str(sample_path)
        
        start = time.time()
        
        # 1. Static Analysis
        try:
            with open(sample_path, 'r', encoding='utf-8', errors='replace') as f:
                code = f.read()
            features = enhanced_static_analysis(code)
            result.static_score = features.get('net_threat', 0)
            result.static_features = features
        except Exception as e:
            logger.error(f"فشل التحليل الثابت {sample_path.name}: {e}")
        
        # 2. Sandbox Runtime
        config = SandboxConfig(
            timeout=self.timeout,
            network_enabled=self.network_enabled,
            max_memory_mb=256,
            max_cpu_percent=80,
        )
        sandbox = SandboxRunner(config)
        sandbox_result = sandbox.run_script(sample_path)
        result.sandbox_result = sandbox_result
        result.sandbox_score = sandbox_result.threat_score
        result.sandbox_anomalies = sandbox_result.anomalies
        
        # 3. Combined Scoring (weighted fusion)
        static_norm = min(result.static_score / 30.0, 1.0) * 100
        runtime_norm = sandbox_result.threat_score
        
        # الوزن: 40% static + 60% runtime
        result.combined_score = (static_norm * 0.4) + (runtime_norm * 0.6)
        
        # جمع threat flags
        all_flags = set()
        if sandbox_result.threat_flags:
            all_flags.update(sandbox_result.threat_flags)
        
        # Static-based flags
        sf = result.static_features
        if sf.get('malicious_encryption', 0) > 15:
            all_flags.add("CRYPTO_ABUSE")
        if sf.get('obfuscation', 0) > 20:
            all_flags.add("HEAVY_OBFUSCATION")
        if sf.get('network_activity', 0) > 10:
            all_flags.add("NETWORK_ACTIVITY")
        if sf.get('process_manipulation', 0) > 10:
            all_flags.add("PROCESS_MANIPULATION")
        if sf.get('data_collection', 0) > 10:
            all_flags.add("DATA_COLLECTION")
        
        result.threat_flags = list(all_flags)
        
        # Verdict
        if result.combined_score >= 50:
            result.verdict = "MALICIOUS"
        elif result.combined_score >= 25:
            result.verdict = "SUSPICIOUS"
        else:
            result.verdict = "CLEAN"
        
        result.duration = time.time() - start
        return result
    
    def analyze_directory(self, samples_dir: Path, file_pattern: str = "*.py") -> List[IntegratedResult]:
        """تحليل كل العينات في مجلد"""
        samples = sorted(samples_dir.glob(file_pattern))
        logger.info(f"بدء تحليل {len(samples)} عينة...")
        
        for i, sample in enumerate(samples, 1):
            sample_name = sample.name
            # تخطي الملفات النظيفة والمساعدة
            if any(x in sample_name for x in ['__init__', 'clean_', 'legitimate']):
                if 'zen_clean_' in sample_name:
                    pass  # نحلل العينات النظيفة
                else:
                    continue
            
            logger.info(f"[{i}/{len(samples)}] تحليل: {sample_name}")
            try:
                result = self.analyze_sample(sample)
                self.results.append(result)
            except Exception as e:
                logger.error(f"فشل تحليل {sample_name}: {e}")
        
        return self.results
    
    def get_detection_stats(self) -> Dict:
        """إحصائيات الكشف"""
        if not self.results:
            return {}
        
        total = len(self.results)
        malicious = sum(1 for r in self.results if r.verdict == "MALICIOUS")
        suspicious = sum(1 for r in self.results if r.verdict == "SUSPICIOUS")
        clean = sum(1 for r in self.results if r.verdict == "CLEAN")
        
        scores = [r.combined_score for r in self.results]
        avg_score = sum(scores) / len(scores) if scores else 0
        
        return {
            "total_samples": total,
            "malicious": malicious,
            "suspicious": suspicious,
            "clean": clean,
            "detection_rate": round((malicious + suspicious) / total * 100, 1) if total > 0 else 0,
            "avg_combined_score": round(avg_score, 1),
            "max_score": max(scores) if scores else 0,
        }
    
    def generate_report(self, output_path: Optional[Path] = None) -> Dict:
        """إنشاء تقرير كامل"""
        stats = self.get_detection_stats()
        
        report = {
            "engine": "Nucleon v5.0 - Integrated Sandbox Runtime",
            "timestamp": time.time(),
            "stats": stats,
            "samples": [],
        }
        
        for r in self.results:
            sample_info = {
                "name": r.sample_name,
                "verdict": r.verdict,
                "combined_score": round(r.combined_score, 1),
                "static_score": round(r.static_score, 1),
                "sandbox_score": round(r.sandbox_score, 1),
                "threat_flags": r.threat_flags,
                "duration": round(r.duration, 2),
            }
            if r.sandbox_result:
                sample_info["sandbox"] = {
                    "cpu_percent": round(r.sandbox_result.cpu_usage_percent, 1),
                    "memory_peak_mb": round(r.sandbox_result.memory_peak_mb, 1),
                    "spawned_children": r.sandbox_result.processes_spawned,
                    "network_connections": len(r.sandbox_result.network_connections),
                    "anomalies": r.sandbox_result.anomalies,
                }
            report["samples"].append(sample_info)
        
        if output_path:
            output_path.parent.mkdir(parents=True, exist_ok=True)
            with open(output_path, 'w', encoding='utf-8') as f:
                json.dump(report, f, indent=2, ensure_ascii=False)
            logger.info(f"تم حفظ التقرير: {output_path}")
        
        return report


def main():
    """تشغيل المحرك المتكامل على جميع العينات"""
    project_root = Path(__file__).parent
    samples_dir = project_root / "dna_engine" / "samples"
    
    print("\n" + "=" * 60)
    print("  Nucleon v5.0 - Integrated Sandbox Runtime Engine")
    print("=" * 60)
    
    engine = IntegratedSandboxEngine(timeout=15, network_enabled=False)
    results = engine.analyze_directory(samples_dir)
    
    # Generate report
    output_dir = project_root / "reports"
    output_dir.mkdir(exist_ok=True)
    report = engine.generate_report(output_dir / "integrated_sandbox_report.json")
    
    # Print summary
    stats = report["stats"]
    print(f"\nTotal Samples: {stats['total_samples']}")
    print(f"MALICIOUS: {stats['malicious']} | SUSPICIOUS: {stats['suspicious']} | CLEAN: {stats['clean']}")
    print(f"Detection Rate: {stats['detection_rate']}%")
    print(f"Avg Score: {stats['avg_combined_score']}")
    
    # Print per-sample results
    print(f"\n{'Sample':<40} {'Verdict':<12} {'Score':>6}")
    print("-" * 60)
    for s in report["samples"]:
        print(f"{s['name']:<40} {s['verdict']:<12} {s['combined_score']:>5.1f}")


if __name__ == "__main__":
    main()
