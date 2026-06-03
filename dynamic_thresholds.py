"""
Nucleon v5.0 - Dynamic Threshold Tuning Engine
ضبط ديناميكي للعتبات - تعلم تلقائي من النتائج وإعادة معايرة
"""
import os
import sys
import json
import time
import numpy as np
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, field

sys.path.insert(0, str(Path(__file__).parent))
from utils.logger import logger

try:
    from sklearn.metrics import f1_score, precision_score, recall_score, roc_auc_score
    SKLEARN_AVAILABLE = True
except ImportError:
    SKLEARN_AVAILABLE = False


@dataclass
class ThresholdConfig:
    """إعدادات العتبات لكل محرك"""
    engine: str = ""
    
    # عتبات (يمكن أن تكون متعددة)
    malicious_threshold: float = 50.0  # فوق هذا = خبيث
    suspicious_threshold: float = 25.0  # فوق هذا = مريب
    
    # أوزان
    weight: float = 1.0
    
    # إحصائيات
    current_f1: float = 0.0
    current_precision: float = 0.0
    current_recall: float = 0.0
    
    # سجل
    history: List[Dict] = field(default_factory=list)


class DynamicThresholdTuner:
    """
    موالف العتبات الديناميكي
    - تعلم من نتائج سابقة
    - ضبط تلقائي للعتبات حسب tolerance المطلوب
    - أنماط معايرة: max_f1, zero_fp, balanced
    """
    
    MODES = {
        'max_f1': 'أقصى F1 Score',
        'zero_fp': 'صفر False Positives',
        'max_recall': 'أقصى نسبة كشف',
        'balanced': 'متوازن (F1 + precision)',
    }
    
    def __init__(self, mode: str = 'max_f1'):
        self.mode = mode
        self.thresholds: Dict[str, ThresholdConfig] = {}
        self._init_defaults()
    
    def _init_defaults(self):
        """تهيئة العتبات الافتراضية"""
        defaults = {
            'ast': (18.0, 8.0, 1.0),
            'yara': (30.0, 15.0, 1.0),
            'runtime': (40.0, 20.0, 1.2),
            'sandbox': (40.0, 20.0, 1.2),
            'pcap': (30.0, 15.0, 0.8),
            'memory': (35.0, 18.0, 1.0),
            'binary': (30.0, 15.0, 0.8),
        }
        
        for engine, (mal, sus, weight) in defaults.items():
            self.thresholds[engine] = ThresholdConfig(
                engine=engine,
                malicious_threshold=mal,
                suspicious_threshold=sus,
                weight=weight,
            )
    
    def collect_results(self, engine_name: str, scores: List[float], labels: List[int]) -> Dict:
        """جمع وتحليل نتائج محرك واحد"""
        if engine_name not in self.thresholds:
            self.thresholds[engine_name] = ThresholdConfig(engine=engine_name)
        
        cfg = self.thresholds[engine_name]
        
        if not scores or not labels:
            return {'error': 'no_data'}
        
        # Find optimal threshold
        best_thresh = 0
        best_metric = 0
        results_history = []
        
        for t in np.arange(5, 95, 5):
            preds = [1 if s >= t else 0 for s in scores]
            
            tp = sum(1 for p, l in zip(preds, labels) if p == 1 and l == 1)
            fp = sum(1 for p, l in zip(preds, labels) if p == 1 and l == 0)
            fn = sum(1 for p, l in zip(preds, labels) if p == 0 and l == 1)
            tn = sum(1 for p, l in zip(preds, labels) if p == 0 and l == 0)
            
            precision = tp / (tp + fp) if (tp + fp) > 0 else 0
            recall = tp / (tp + fn) if (tp + fn) > 0 else 0
            f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0
            fp_rate = fp / (fp + tn) if (fp + tn) > 0 else 0
            
            metric_map = {
                'max_f1': f1,
                'zero_fp': 1 - fp_rate if fp_rate == 0 else -fp_rate,
                'max_recall': recall,
                'balanced': (f1 + precision) / 2,
            }
            
            current_metric = metric_map.get(self.mode, f1)
            
            results_history.append({
                'threshold': float(t),
                'tp': tp, 'fp': fp, 'fn': fn, 'tn': tn,
                'precision': round(precision, 3),
                'recall': round(recall, 3),
                'f1': round(f1, 3),
                'fp_rate': round(fp_rate, 3),
            })
            
            if current_metric > best_metric:
                best_metric = current_metric
                best_thresh = t
        
        # Update thresholds
        cfg.malicious_threshold = float(best_thresh)
        cfg.suspicious_threshold = float(best_thresh * 0.5)
        cfg.history.extend(results_history)
        
        # Get metrics at best threshold
        best_result = next(
            (r for r in results_history if r['threshold'] == best_thresh),
            results_history[-1] if results_history else {}
        )
        
        cfg.current_f1 = best_result.get('f1', 0)
        cfg.current_precision = best_result.get('precision', 0)
        cfg.current_recall = best_result.get('recall', 0)
        
        return {
            'engine': engine_name,
            'optimal_threshold': float(best_thresh),
            'f1_at_optimal': round(cfg.current_f1, 3),
            'precision': round(cfg.current_precision, 3),
            'recall': round(cfg.current_recall, 3),
            'mode': self.mode,
        }
    
    def compute_combined_threshold(self, engine_scores: Dict[str, float]) -> Tuple[float, str]:
        """حساب الدرجة المجمعة مع العتبات الديناميكية"""
        weighted_sum = 0.0
        total_weight = 0.0
        
        for engine, score in engine_scores.items():
            cfg = self.thresholds.get(engine)
            if not cfg:
                continue
            
            # Normalize: score relative to malicious threshold
            normalized = min(score / (cfg.malicious_threshold or 1) * 50, 100)
            weighted_sum += normalized * cfg.weight
            total_weight += cfg.weight
        
        if total_weight == 0:
            return 0.0, "CLEAN"
        
        combined = weighted_sum / total_weight
        
        # Dynamic verdict
        if combined >= 45:
            verdict = "MALICIOUS"
        elif combined >= 22:
            verdict = "SUSPICIOUS"
        else:
            verdict = "CLEAN"
        
        return combined, verdict
    
    def calibrate_all(self, all_results: Dict[str, Tuple[List[float], List[int]]]) -> Dict:
        """معايرة كل المحركات دفعة واحدة"""
        report = {}
        
        for engine, (scores, labels) in all_results.items():
            if not scores:
                continue
            result = self.collect_results(engine, scores, labels)
            report[engine] = result
        
        return report
    
    def get_optimal_weights(self, performance_history: Dict[str, List[Dict]]) -> Dict[str, float]:
        """حساب أوزان مثالية بناءً على أداء كل محرك"""
        weights = {}
        f1_scores = {}
        
        for engine, history in performance_history.items():
            if not history:
                f1_scores[engine] = 0.0
                continue
            
            # Average F1 of last N runs
            recent = history[-5:]
            avg_f1 = np.mean([h.get('f1', 0) for h in recent])
            f1_scores[engine] = avg_f1
        
        total_f1 = sum(f1_scores.values()) or 1
        for engine, f1 in f1_scores.items():
            weights[engine] = f1 / total_f1
        
        return weights
    
    def save_config(self, output_path: Path):
        """حفظ إعدادات العتبات"""
        config = {
            'mode': self.mode,
            'thresholds': {},
        }
        
        for engine, cfg in self.thresholds.items():
            config['thresholds'][engine] = {
                'malicious_threshold': cfg.malicious_threshold,
                'suspicious_threshold': cfg.suspicious_threshold,
                'weight': cfg.weight,
                'current_f1': cfg.current_f1,
                'current_precision': cfg.current_precision,
                'current_recall': cfg.current_recall,
            }
        
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(config, f, indent=2, ensure_ascii=False)
        
        logger.info(f"تم حفظ العتبات الديناميكية: {output_path}")
    
    def load_config(self, input_path: Path):
        """تحميل إعدادات العتبات"""
        with open(input_path, 'r', encoding='utf-8') as f:
            config = json.load(f)
        
        self.mode = config.get('mode', self.mode)
        
        for engine, eng_cfg in config.get('thresholds', {}).items():
            if engine in self.thresholds:
                cfg = self.thresholds[engine]
            else:
                cfg = ThresholdConfig(engine=engine)
                self.thresholds[engine] = cfg
            
            cfg.malicious_threshold = eng_cfg['malicious_threshold']
            cfg.suspicious_threshold = eng_cfg['suspicious_threshold']
            cfg.weight = eng_cfg.get('weight', 1.0)
            cfg.current_f1 = eng_cfg.get('current_f1', 0.0)
            cfg.current_precision = eng_cfg.get('current_precision', 0.0)
            cfg.current_recall = eng_cfg.get('current_recall', 0.0)


# Singleton
_tuner = None

def get_tuner(mode: str = 'max_f1') -> DynamicThresholdTuner:
    global _tuner
    if _tuner is None:
        _tuner = DynamicThresholdTuner(mode=mode)
    return _tuner
