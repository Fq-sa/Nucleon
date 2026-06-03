"""
Nucleon v5.0 - XGBoost ML Classifier
مصنف تعلم آلي يجمع نتائج كل المحركات السبعة ويتعلم thresholds المثالية
"""
import os
import sys
import json
import time
import numpy as np
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, field
from collections import defaultdict

sys.path.insert(0, str(Path(__file__).parent))
from utils.logger import logger

try:
    import xgboost as xgb
    XGB_AVAILABLE = True
except ImportError:
    XGB_AVAILABLE = False
    logger.error("xgboost غير مثبت. استخدم: pip install xgboost")


@dataclass
class EnsembledSample:
    """عينة مع نتائج كل المحركات"""
    name: str = ""
    label: int = 0  # 0=clean, 1=malware
    
    # 7 engine scores (0-100)
    ast_score: float = 0.0
    yara_score: float = 0.0
    runtime_score: float = 0.0
    sandbox_score: float = 0.0
    pcap_score: float = 0.0
    memory_score: float = 0.0
    binary_score: float = 0.0
    
    # Derived features
    engine_count: int = 0  # عدد المحركات اللي اكتشفت شي
    max_engine_score: float = 0.0
    mean_engine_score: float = 0.0
    score_variance: float = 0.0
    
    # Final
    predicted: int = 0
    confidence: float = 0.0


class XGBoostEnsembleClassifier:
    """
    مصنف XGBoost يجمع مخرجات 7 محركات
    - تدريب على scores مجمعة
    - معايرة thresholds تلقائياً
    - Feature importance لكل محرك
    """
    
    def __init__(self):
        self.model = None
        self.feature_importance: Dict[str, float] = {}
        self.optimal_threshold: float = 50.0
        self.trained = False
        
        # أوزان افتراضية لكل محرك
        self.default_weights = {
            'ast': 0.25,
            'yara': 0.15,
            'runtime': 0.20,
            'sandbox': 0.20,
            'pcap': 0.05,
            'memory': 0.10,
            'binary': 0.05,
        }
    
    def _prepare_features(self, samples: List[EnsembledSample]) -> np.ndarray:
        """تحضير مصفوفة الميزات"""
        features = []
        for s in samples:
            feat_vec = [
                s.ast_score,
                s.yara_score,
                s.runtime_score,
                s.sandbox_score,
                s.pcap_score,
                s.memory_score,
                s.binary_score,
                s.engine_count,
                s.max_engine_score,
                s.mean_engine_score,
                s.score_variance,
            ]
            features.append(feat_vec)
        
        return np.array(features, dtype=np.float32)
    
    def train_from_file(self, training_data_path: Path) -> Dict:
        """
        تدريب من ملف JSON يحتوي على نتائج مصنفة
        تنسيق الملف:
        {
          "samples": [
            {
              "name": "sample.py",
              "label": 1,  // 0=clean, 1=malware
              "scores": {"ast": 25.0, "yara": 15.0, ...}
            }
          ]
        }
        """
        with open(training_data_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
        
        samples = []
        for item in data.get('samples', []):
            s = EnsembledSample(
                name=item.get('name', 'unknown'),
                label=item.get('label', 0),
                **item.get('scores', {}),
            )
            s.engine_count = sum(1 for v in [
                s.ast_score, s.yara_score, s.runtime_score,
                s.sandbox_score, s.pcap_score, s.memory_score, s.binary_score
            ] if v > 0)
            scores_arr = [
                s.ast_score, s.yara_score, s.runtime_score,
                s.sandbox_score, s.pcap_score, s.memory_score, s.binary_score
            ]
            s.max_engine_score = max(scores_arr)
            s.mean_engine_score = sum(scores_arr) / len(scores_arr)
            s.score_variance = np.var(scores_arr) if len(scores_arr) > 1 else 0
            samples.append(s)
        
        return self.train(samples)
    
    def train(self, samples: List[EnsembledSample]) -> Dict:
        """تدريب النموذج على العينات"""
        if not XGB_AVAILABLE:
            return self._fallback_train(samples)
        
        if len(samples) < 8:
            logger.warning(f"عدد العينات قليل ({len(samples)}). استخدام fallback.")
            return self._fallback_train(samples)
        
        X = self._prepare_features(samples)
        y = np.array([s.label for s in samples], dtype=np.int32)
        
        # XGBoost classifier
        self.model = xgb.XGBClassifier(
            n_estimators=100,
            max_depth=4,
            learning_rate=0.1,
            subsample=0.8,
            colsample_bytree=0.8,
            use_label_encoder=False,
            eval_metric='logloss',
            random_state=42,
        )
        
        self.model.fit(X, y)
        
        # Feature importance
        feat_names = [
            'ast_score', 'yara_score', 'runtime_score', 'sandbox_score',
            'pcap_score', 'memory_score', 'binary_score',
            'engine_count', 'max_score', 'mean_score', 'variance',
        ]
        
        importances = self.model.feature_importances_
        self.feature_importance = {
            name: float(imp) for name, imp in zip(feat_names, importances)
        }
        
        # Find optimal threshold via prediction on training data
        probs = self.model.predict_proba(X)
        mal_probs = probs[:, 1]  # احتمالية malware
        
        # Find threshold that maximizes F1 (simple approach)
        best_f1 = 0
        best_thresh = 0.5
        for t in np.arange(0.1, 0.9, 0.05):
            preds = (mal_probs >= t).astype(int)
            tp = ((preds == 1) & (y == 1)).sum()
            fp = ((preds == 1) & (y == 0)).sum()
            fn = ((preds == 0) & (y == 1)).sum()
            
            precision = tp / (tp + fp) if (tp + fp) > 0 else 0
            recall = tp / (tp + fn) if (tp + fn) > 0 else 0
            f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0
            
            if f1 > best_f1:
                best_f1 = f1
                best_thresh = t
        
        self.optimal_threshold = float(best_thresh)
        self.trained = True
        
        return {
            'status': 'trained',
            'samples_count': len(samples),
            'feature_importance': self.feature_importance,
            'optimal_threshold': round(self.optimal_threshold, 3),
            'model_type': 'XGBoost',
        }
    
    def _fallback_train(self, samples: List[EnsembledSample]) -> Dict:
        """Fallback: أوزان يدوية معايرة"""
        if not samples:
            return {'status': 'no_data'}
        
        # Learn optimal weights from labeled data
        mal_scores = defaultdict(list)
        clean_scores = defaultdict(list)
        
        engine_names = ['ast', 'yara', 'runtime', 'sandbox', 'pcap', 'memory', 'binary']
        engine_attrs = ['ast_score', 'yara_score', 'runtime_score', 'sandbox_score', 
                        'pcap_score', 'memory_score', 'binary_score']
        
        for s in samples:
            for name, attr in zip(engine_names, engine_attrs):
                score = getattr(s, attr, 0)
                if s.label == 1:
                    mal_scores[name].append(score)
                else:
                    clean_scores[name].append(score)
        
        # Calculate discriminative power per engine
        self.feature_importance = {}
        for name in engine_names:
            mal_avg = np.mean(mal_scores[name]) if mal_scores[name] else 0
            clean_avg = np.mean(clean_scores[name]) if clean_scores[name] else 0
            diff = mal_avg - clean_avg
            self.feature_importance[name] = max(diff, 0)
        
        total = sum(self.feature_importance.values()) or 1
        for name in self.feature_importance:
            self.feature_importance[name] /= total
        
        self.trained = True
        return {
            'status': 'fallback_trained',
            'samples_count': len(samples),
            'feature_importance': self.feature_importance,
            'training_type': 'statistical_fallback',
        }
    
    def predict(self, sample: EnsembledSample) -> Tuple[int, float]:
        """توقع label عينة جديدة"""
        if not self.trained:
            return 0, 0.0
        
        # Compute weighted score
        scores = {
            'ast': sample.ast_score,
            'yara': sample.yara_score,
            'runtime': sample.runtime_score,
            'sandbox': sample.sandbox_score,
            'pcap': sample.pcap_score,
            'memory': sample.memory_score,
            'binary': sample.binary_score,
        }
        
        if self.model and XGB_AVAILABLE:
            X = self._prepare_features([sample])
            proba = self.model.predict_proba(X)[0]
            pred = int(proba[1] >= self.optimal_threshold)
            confidence = float(proba[1])
        else:
            # Weighted sum fallback
            weighted = sum(
                scores[name] * self.feature_importance.get(name, self.default_weights[name])
                for name in scores
            )
            weighted = min(weighted, 100)
            pred = 1 if weighted >= 40 else 0
            confidence = weighted / 100.0
        
        return pred, confidence
    
    def calibrate_thresholds(self, scores: List[float], labels: List[int]) -> Dict:
        """معايرة ديناميكية للعتبات لكل محرك"""
        thresholds = {}
        
        for engine in ['ast', 'yara', 'runtime', 'sandbox', 'pcap', 'memory', 'binary']:
            eng_scores = []
            best_t = 0
            best_f1 = 0
            
            for t in range(0, 101, 5):
                tp = fp = fn = tn = 0
                for score, label in zip(scores, labels):
                    pred = 1 if score >= t else 0
                    if pred == 1 and label == 1: tp += 1
                    elif pred == 1 and label == 0: fp += 1
                    elif pred == 0 and label == 1: fn += 1
                
                precision = tp / (tp + fp) if (tp + fp) > 0 else 0
                recall = tp / (tp + fn) if (tp + fn) > 0 else 0
                f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0
                
                if f1 > best_f1:
                    best_f1 = f1
                    best_t = t
            
            thresholds[engine] = best_t
        
        return thresholds
    
    def save_model(self, output_path: Path):
        """حفظ النموذج المدرب"""
        output_path.parent.mkdir(parents=True, exist_ok=True)
        
        data = {
            'model_type': 'XGBoost' if self.model and XGB_AVAILABLE else 'StatisticalFallback',
            'trained': self.trained,
            'feature_importance': self.feature_importance,
            'optimal_threshold': self.optimal_threshold,
            'default_weights': self.default_weights,
        }
        
        if self.model and XGB_AVAILABLE:
            # Save native XGBoost model
            native_path = output_path.parent / "xgboost_native.json"
            self.model.save_model(str(native_path))
            data['native_model_path'] = str(native_path)
            logger.info(f"تم حفظ نموذج XGBoost الأصلي: {native_path}")
        
        with open(output_path, 'w') as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        
        logger.info(f"تم حفظ النموذج: {output_path}")
    
    def load_model(self, config_path: Path):
        """تحميل النموذج"""
        with open(config_path, 'r') as f:
            data = json.load(f)
        
        self.feature_importance = data.get('feature_importance', self.default_weights)
        self.optimal_threshold = data.get('optimal_threshold', 50.0)
        self.trained = data.get('trained', False)
        self.default_weights = data.get('default_weights', self.default_weights)
        
        if data.get('native_model_path') and XGB_AVAILABLE:
            native_path = Path(data['native_model_path'])
            if native_path.exists():
                self.model = xgb.XGBClassifier()
                self.model.load_model(str(native_path))
                logger.info(f"تم تحميل نموذج XGBoost الأصلي: {native_path}")
        
        logger.info(f"تم تحميل تكوين النموذج: {config_path} (trained={self.trained})")


# Singleton
_classifier = None

def get_classifier() -> XGBoostEnsembleClassifier:
    global _classifier
    if _classifier is None:
        _classifier = XGBoostEnsembleClassifier()
    return _classifier
