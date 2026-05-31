"""
Comparison Engine
محرك المقارنة - يحسب المسافة السلوكية بين بصمتين
"""
import numpy as np
from typing import Dict, List, Tuple
from scipy.spatial.distance import cosine, euclidean
from .dna_fingerprint import DNAFingerprint
from utils.logger import logger


class ComparisonEngine:
    def __init__(self):
        self.feature_weights = {
            'timing': 0.20,
            'memory': 0.20,
            'io': 0.15,
            'network': 0.10,
            'file': 0.05,
            'process': 0.10,
            'rhythm': 0.10,
            'entropy': 0.10
        }
        
    def calculate_similarity(self, fp1: DNAFingerprint, fp2: DNAFingerprint) -> Dict:
        logger.info("حساب التشابه السلوكي")
        
        similarities = {
            'timing': self._calculate_feature_similarity(fp1.timing_vector, fp2.timing_vector),
            'memory': self._calculate_feature_similarity(fp1.memory_vector, fp2.memory_vector),
            'io': self._calculate_feature_similarity(fp1.io_vector, fp2.io_vector),
            'network': self._calculate_feature_similarity(fp1.network_vector, fp2.network_vector),
            'file': self._calculate_feature_similarity(fp1.file_vector, fp2.file_vector),
            'process': self._calculate_feature_similarity(fp1.process_vector, fp2.process_vector),
            'rhythm': self._calculate_feature_similarity(fp1.rhythm_vector, fp2.rhythm_vector),
            'entropy': self._calculate_feature_similarity(fp1.entropy_vector, fp2.entropy_vector)
        }
        
        weighted_similarity = sum(
            similarities[feature] * weight
            for feature, weight in self.feature_weights.items()
        )
        
        result = {
            'overall_similarity': weighted_similarity,
            'feature_similarities': similarities,
            'match': weighted_similarity > 0.75,
            'suspicious': weighted_similarity > 0.85,
            'distances': self._calculate_distances(fp1, fp2)
        }
        
        logger.info(f"التشابه الكلي: {weighted_similarity:.3f}")
        return result
        
    def _calculate_feature_similarity(self, vec1: List[float], vec2: List[float]) -> float:
        try:
            arr1 = np.array(vec1)
            arr2 = np.array(vec2)
            
            if np.all(arr1 == 0) and np.all(arr2 == 0):
                return 1.0
                
            if np.all(arr1 == 0) or np.all(arr2 == 0):
                return 0.0
                
            cosine_sim = 1 - cosine(arr1, arr2)
            return float(cosine_sim)
        except Exception as e:
            logger.error(f"خطأ في حساب التشابه: {e}")
            return 0.0
            
    def _calculate_distances(self, fp1: DNAFingerprint, fp2: DNAFingerprint) -> Dict[str, float]:
        distances = {}
        
        combined1 = np.concatenate([
            fp1.timing_vector, fp1.memory_vector,
            fp1.io_vector, fp1.network_vector, fp1.file_vector,
            fp1.process_vector, fp1.rhythm_vector, fp1.entropy_vector
        ])
        
        combined2 = np.concatenate([
            fp2.timing_vector, fp2.memory_vector,
            fp2.io_vector, fp2.network_vector, fp2.file_vector,
            fp2.process_vector, fp2.rhythm_vector, fp2.entropy_vector
        ])
        
        distances['euclidean'] = float(euclidean(combined1, combined2))
        distances['cosine'] = float(cosine(combined1, combined2))
        distances['manhattan'] = float(np.sum(np.abs(combined1 - combined2)))
        
        return distances
