"""
Vector Database for Behavioral DNA Fingerprints v4.0
قاعدة بيانات متجهة باستخدام FAISS لتسريع البحث السلوكي

Academic Research: High-dimensional similarity search for malware DNA
يحول البصمات السلوكية ٩٦-بعد إلى فضاء متجه ويبحث بأداء عالي
"""

import os
import sys
import json
import time
import pickle
import hashlib
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, field
import numpy as np

sys.path.insert(0, str(Path(__file__).parent.parent))
from utils.logger import logger

# Try importing FAISS
try:
    import faiss
    FAISS_AVAILABLE = True
except ImportError:
    FAISS_AVAILABLE = False
    logger.warning("faiss-cpu غير مثبت. سيتم استخدام numpy كبديل.")


@dataclass
class VectorEntry:
    """Single entry in vector database"""
    id: str
    vector: np.ndarray
    metadata: Dict = field(default_factory=dict)
    timestamp: float = field(default_factory=time.time)
    label: str = ""  # 'malware', 'clean', 'unknown'
    family: str = ""  # malware family name


class VectorDB:
    """
    FAISS-based vector database for behavioral fingerprints
    Supports fast similarity search across thousands of samples
    """
    
    def __init__(self, db_path: Optional[Path] = None, dimension: int = 96):
        self.dimension = dimension
        self.db_path = db_path or (Path(__file__).parent / "vector_index.faiss")
        self.index = None
        self.entries: Dict[int, VectorEntry] = {}
        self._next_id = 0
        
        self._load_or_create()
    
    def _load_or_create(self):
        """Load existing index or create new one"""
        meta_path = self.db_path.with_suffix('.meta')
        index_path = self.db_path.with_suffix('.index')
        
        if FAISS_AVAILABLE and index_path.exists() and meta_path.exists():
            try:
                self.index = faiss.read_index(str(index_path))
                with open(meta_path, 'rb') as f:
                    meta = pickle.load(f)
                    self.entries = meta.get('entries', {})
                    self._next_id = meta.get('next_id', 0)
                    self.dimension = meta.get('dimension', 96)
                logger.info(f"تم تحميل قاعدة المتجهات: {len(self.entries)} بصمة")
            except Exception as e:
                logger.error(f"خطأ في تحميل قاعدة المتجهات: {e}")
                self._create_index()
        else:
            self._create_index()
    
    def _create_index(self):
        """Create a new FAISS index"""
        if FAISS_AVAILABLE:
            # Use IVF for large datasets, FlatL2 for small
            if len(self.entries) > 1000:
                quantizer = faiss.IndexFlatL2(self.dimension)
                self.index = faiss.IndexIVFFlat(
                    quantizer, self.dimension,
                    min(100, len(self.entries) // 10)
                )
            else:
                self.index = faiss.IndexFlatL2(self.dimension)
            
            logger.info(f"تم إنشاء فهرس متجهات جديد ({self.dimension}-بعد)")
        else:
            self.index = None
    
    def _save(self):
        """Save index to disk"""
        if not FAISS_AVAILABLE or self.index is None:
            return
        
        index_path = self.db_path.with_suffix('.index')
        meta_path = self.db_path.with_suffix('.meta')
        
        try:
            faiss.write_index(self.index, str(index_path))
            
            meta = {
                'entries': self.entries,
                'next_id': self._next_id,
                'dimension': self.dimension,
                'total_vectors': self.count(),
            }
            
            with open(meta_path, 'wb') as f:
                pickle.dump(meta, f)
            
            logger.info(f"تم حفظ قاعدة المتجهات: {self.count()} بصمة")
        except Exception as e:
            logger.error(f"خطأ في حفظ قاعدة المتجهات: {e}")
    
    def add(self, vector: np.ndarray, metadata: Dict = None, 
            label: str = "unknown", family: str = "") -> str:
        """
        Add a vector to the database
        Returns the entry ID
        """
        # Normalize vector
        vec = np.array(vector, dtype=np.float32)
        if vec.shape[0] != self.dimension:
            vec = self._pad_or_truncate(vec)
        
        # L2 normalize for cosine similarity
        faiss.normalize_L2(vec.reshape(1, -1))
        
        entry_id = f"vec_{self._next_id}_{int(time.time())}"
        entry = VectorEntry(
            id=entry_id,
            vector=vec,
            metadata=metadata or {},
            label=label,
            family=family,
        )
        
        self.entries[self._next_id] = entry
        
        if FAISS_AVAILABLE and self.index is not None:
            self.index.add(vec.reshape(1, -1))
        
        self._next_id += 1
        
        # Auto-save every 50 additions
        if self._next_id % 50 == 0:
            self._save()
        
        return entry_id
    
    def add_batch(self, vectors: List[np.ndarray], metadatas: List[Dict] = None,
                  labels: List[str] = None, families: List[str] = None) -> List[str]:
        """Add multiple vectors at once"""
        ids = []
        vecs = []
        
        for i, vec in enumerate(vectors):
            v = np.array(vec, dtype=np.float32)
            if v.shape[0] != self.dimension:
                v = self._pad_or_truncate(v)
            
            faiss.normalize_L2(v.reshape(1, -1))
            vecs.append(v)
            
            entry_id = f"vec_{self._next_id}_{int(time.time())}"
            entry = VectorEntry(
                id=entry_id,
                vector=v,
                metadata=metadatas[i] if metadatas else {},
                label=labels[i] if labels else "unknown",
                family=families[i] if families else "",
            )
            self.entries[self._next_id] = entry
            ids.append(entry_id)
            self._next_id += 1
        
        if FAISS_AVAILABLE and self.index is not None and vecs:
            stacked = np.vstack(vecs)
            faiss.normalize_L2(stacked)
            self.index.add(stacked)
        
        self._save()
        return ids
    
    def search(self, query_vector: np.ndarray, k: int = 10) -> List[Dict]:
        """
        Search for k nearest neighbors
        Returns list of results with similarity scores
        """
        query = np.array(query_vector, dtype=np.float32)
        if query.shape[0] != self.dimension:
            query = self._pad_or_truncate(query)
        
        query = query.reshape(1, -1)
        faiss.normalize_L2(query)
        
        if FAISS_AVAILABLE and self.index is not None and self.count() > 0:
            k = min(k, self.count())
            distances, indices = self.index.search(query, k)
            
            results = []
            for i in range(k):
                idx = int(indices[0][i])
                if idx >= 0 and idx in self.entries:
                    entry = self.entries[idx]
                    # Convert L2 distance to similarity score (0-1)
                    similarity = 1.0 / (1.0 + float(distances[0][i]))
                    
                    results.append({
                        'id': entry.id,
                        'label': entry.label,
                        'family': entry.family,
                        'similarity': similarity,
                        'distance': float(distances[0][i]),
                        'metadata': entry.metadata,
                        'timestamp': entry.timestamp,
                    })
            
            return results
        else:
            return self._fallback_search(query_vector, k)
    
    def _fallback_search(self, query_vector: np.ndarray, k: int = 10) -> List[Dict]:
        """Fallback search using numpy when FAISS is not available"""
        query = np.array(query_vector, dtype=np.float32)
        
        similarities = []
        for idx, entry in self.entries.items():
            vec = entry.vector
            # Cosine similarity
            dot = np.dot(query, vec)
            norm_q = np.linalg.norm(query)
            norm_v = np.linalg.norm(vec)
            
            if norm_q == 0 or norm_v == 0:
                sim = 0.0
            else:
                sim = dot / (norm_q * norm_v)
            
            similarities.append((idx, sim, entry))
        
        similarities.sort(key=lambda x: x[1], reverse=True)
        
        results = []
        for idx, sim, entry in similarities[:k]:
            results.append({
                'id': entry.id,
                'label': entry.label,
                'family': entry.family,
                'similarity': sim,
                'distance': 1.0 - sim,
                'metadata': entry.metadata,
                'timestamp': entry.timestamp,
            })
        
        return results
    
    def range_search(self, query_vector: np.ndarray, threshold: float = 0.7) -> List[Dict]:
        """Search for vectors with similarity above threshold"""
        k = max(self.count(), 50)
        all_results = self.search(query_vector, k=k)
        
        return [r for r in all_results if r['similarity'] >= threshold]
    
    def get_by_label(self, label: str) -> List[VectorEntry]:
        """Get all entries with a specific label"""
        return [e for e in self.entries.values() if e.label == label]
    
    def get_by_family(self, family: str) -> List[VectorEntry]:
        """Get all entries in a malware family"""
        return [e for e in self.entries.values() if e.family == family]
    
    def delete(self, entry_id: str):
        """Delete an entry by ID (requires rebuild)"""
        to_delete = None
        for idx, entry in self.entries.items():
            if entry.id == entry_id:
                to_delete = idx
                break
        
        if to_delete is not None:
            del self.entries[to_delete]
            self._rebuild_index()
    
    def _rebuild_index(self):
        """Rebuild FAISS index (needed after deletions)"""
        if not FAISS_AVAILABLE:
            return
        
        self._create_index()
        
        if self.entries:
            vectors = []
            for entry in self.entries.values():
                vectors.append(entry.vector)
            stacked = np.vstack(vectors)
            faiss.normalize_L2(stacked)
            self.index.add(stacked)
        
        self._save()
    
    def count(self) -> int:
        """Return number of entries"""
        return len(self.entries)
    
    def get_stats(self) -> Dict:
        """Get database statistics"""
        labels = {}
        families = {}
        
        for entry in self.entries.values():
            labels[entry.label] = labels.get(entry.label, 0) + 1
            if entry.family:
                families[entry.family] = families.get(entry.family, 0) + 1
        
        return {
            'total_vectors': self.count(),
            'dimension': self.dimension,
            'labels': labels,
            'families': families,
            'index_type': type(self.index).__name__ if self.index else 'numpy_fallback',
        }
    
    def _pad_or_truncate(self, vec: np.ndarray) -> np.ndarray:
        """Ensure vector is the correct dimension"""
        if vec.shape[0] > self.dimension:
            return vec[:self.dimension]
        elif vec.shape[0] < self.dimension:
            padded = np.zeros(self.dimension, dtype=np.float32)
            padded[:vec.shape[0]] = vec
            return padded
        return vec
    
    def fingerprint_to_vector(self, fingerprint) -> np.ndarray:
        """Convert DNAFingerprint to a 96-dim vector for FAISS"""
        vectors = []
        
        attrs = [
            'timing_vector', 'memory_vector', 'io_vector',
            'network_vector', 'file_vector', 'process_vector',
            'rhythm_vector', 'entropy_vector',
        ]
        
        for attr in attrs:
            if hasattr(fingerprint, attr):
                v = getattr(fingerprint, attr)
                if isinstance(v, (list, np.ndarray)):
                    vectors.extend(list(v))
        
        # Pad to 96 dimensions
        vec = np.array(vectors[:96], dtype=np.float32)
        if vec.shape[0] < 96:
            vec = np.pad(vec, (0, 96 - vec.shape[0]), 'constant')
        
        return vec[:96]


class VectorDBManager:
    """
    High-level manager for the vector database
    Handles fingerprint conversion and bulk operations
    """
    
    _instance = None
    
    def __new__(cls, *args, **kwargs):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._initialized = False
        return cls._instance
    
    def __init__(self, db_path: Optional[Path] = None):
        if self._initialized:
            return
        
        self.db_path = db_path or (Path(__file__).parent / "nucleon_vectors")
        self.db = VectorDB(self.db_path)
        self._initialized = True
    
    def index_sample(self, fingerprint, name: str, label: str = "unknown",
                     family: str = "", metadata: Dict = None) -> str:
        """Index a behavioral fingerprint"""
        vec = self.db.fingerprint_to_vector(fingerprint)
        meta = {
            'name': name,
            'indexed_at': time.time(),
            **(metadata or {}),
        }
        return self.db.add(vec, meta, label, family)
    
    def query_sample(self, fingerprint, k: int = 10) -> List[Dict]:
        """Query similar fingerprints"""
        vec = self.db.fingerprint_to_vector(fingerprint)
        return self.db.search(vec, k)
    
    def is_known_malware(self, fingerprint, threshold: float = 0.85) -> Tuple[bool, Dict]:
        """Check if fingerprint matches known malware"""
        results = self.query_sample(fingerprint, k=5)
        
        for r in results:
            if r['label'] == 'malware' and r['similarity'] >= threshold:
                return True, r
        
        return False, {}
    
    def classify_sample(self, fingerprint) -> Dict:
        """Classify a sample based on nearest neighbors"""
        results = self.query_sample(fingerprint, k=10)
        
        if not results:
            return {
                'label': 'unknown',
                'confidence': 0.0,
                'nearest_family': None,
                'nearest_similarity': 0.0,
            }
        
        # Weighted voting by similarity
        label_votes = {}
        family_votes = {}
        total_weight = 0
        
        for r in results:
            weight = r['similarity']
            label_votes[r['label']] = label_votes.get(r['label'], 0) + weight
            if r['family']:
                family_votes[r['family']] = family_votes.get(r['family'], 0) + weight
            total_weight += weight
        
        best_label = max(label_votes, key=label_votes.get) if label_votes else 'unknown'
        confidence = label_votes.get(best_label, 0) / total_weight if total_weight > 0 else 0
        nearest_family = max(family_votes, key=family_votes.get) if family_votes else None
        
        return {
            'label': best_label,
            'confidence': confidence,
            'nearest_family': nearest_family,
            'nearest_similarity': results[0]['similarity'] if results else 0,
            'label_votes': label_votes,
            'family_votes': family_votes,
            'top_matches': results[:3],
        }
    
    def get_database_stats(self) -> Dict:
        """Get comprehensive database statistics"""
        stats = self.db.get_stats()
        
        # Add vector quality metrics
        if self.db.entries:
            all_vecs = []
            for entry in self.db.entries.values():
                all_vecs.append(entry.vector)
            
            if all_vecs:
                stacked = np.vstack(all_vecs)
                stats['vector_mean_norm'] = float(np.mean(np.linalg.norm(stacked, axis=1)))
                stats['vector_std_norm'] = float(np.std(np.linalg.norm(stacked, axis=1)))
                stats['sparsity'] = float(np.mean(stacked == 0))
        
        return stats


# Convenience function
def get_vector_db() -> VectorDBManager:
    """Get singleton vector DB manager"""
    return VectorDBManager()
