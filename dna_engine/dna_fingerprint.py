"""
DNA Fingerprint Generator
محرك توليد الحمض النووي السلوكي - يحول البيانات السلوكية إلى بصمة رقمية
"""
import hashlib
import json
from typing import Dict, List, Optional
from dataclasses import dataclass, asdict
import numpy as np
from .behavior_analyzer import BehavioralData
from utils.logger import logger


@dataclass
class DNAFingerprint:
    timing_vector: List[float]
    memory_vector: List[float]
    io_vector: List[float]
    network_vector: List[float]
    file_vector: List[float]
    process_vector: List[float]
    rhythm_vector: List[float]
    entropy_vector: List[float]
    
    raw_hash: str
    creation_timestamp: float
    
    def to_dict(self) -> Dict:
        return asdict(self)
        
    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2)


class DNAEngine:
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
        
    def generate_fingerprint(self, behavioral_data: BehavioralData) -> DNAFingerprint:
        logger.info("بدء توليد البصمة السلوكية")
        
        timing_vector = self._extract_timing_features(behavioral_data)
        memory_vector = self._extract_memory_features(behavioral_data)
        io_vector = self._extract_io_features(behavioral_data)
        network_vector = self._extract_network_features(behavioral_data)
        file_vector = self._extract_file_features(behavioral_data)
        process_vector = self._extract_process_features(behavioral_data)
        rhythm_vector = self._extract_rhythm_features(behavioral_data)
        entropy_vector = self._extract_entropy_features(behavioral_data)
        
        combined_data = {
            'timing': timing_vector,
            'memory': memory_vector,
            'io': io_vector,
            'network': network_vector,
            'file': file_vector,
            'process': process_vector,
            'rhythm': rhythm_vector,
            'entropy': entropy_vector
        }
        
        raw_hash = self._compute_hash(combined_data)
        
        fingerprint = DNAFingerprint(
            timing_vector=timing_vector,
            memory_vector=memory_vector,
            io_vector=io_vector,
            network_vector=network_vector,
            file_vector=file_vector,
            process_vector=process_vector,
            rhythm_vector=rhythm_vector,
            entropy_vector=entropy_vector,
            raw_hash=raw_hash,
            creation_timestamp=time.time()
        )
        
        logger.info(f"تم توليد البصمة: {raw_hash[:16]}...")
        return fingerprint
        
    def _extract_timing_features(self, data: BehavioralData) -> List[float]:
        patterns = data.timing_patterns
        if not patterns:
            return [0.0] * 12
            
        arr = np.array(patterns)
        
        # Basic stats
        mean_val = float(np.mean(arr))
        std_val = float(np.std(arr))
        min_val = float(np.min(arr))
        max_val = float(np.max(arr))
        
        # Coefficient of variation (how variable the timing is)
        cv = std_val / mean_val if mean_val > 0 else 0.0
        
        # Burst ratio (how many samples are very fast)
        fast_threshold = 0.11  # 0.1s sleep + overhead
        burst_ratio = float(np.sum(arr < fast_threshold)) / len(arr)
        
        # Slow ratio (idle periods)
        slow_ratio = float(np.sum(arr > 0.5)) / len(arr)
        
        # Periodicity detection - autocorrelation at lag 1
        if len(arr) > 10:
            autocorr = float(np.corrcoef(arr[:-1], arr[1:])[0, 1])
            if np.isnan(autocorr):
                autocorr = 0.0
        else:
            autocorr = 0.0
        
        # Sleep regularity (low std/mean = regular sleep = bot-like)
        regularity = 1.0 - min(cv, 1.0)
        
        # Timing density (operations per second)
        total_time = float(np.sum(arr))
        density = len(arr) / total_time if total_time > 0 else 0.0
        density = min(density / 100.0, 1.0)  # normalize to 0-1
        
        # Jitter (variance in inter-sample timing)
        if len(arr) > 2:
            diffs = np.diff(arr)
            jitter = float(np.std(diffs))
        else:
            jitter = 0.0
        
        return [
            min(mean_val, 1.0),
            min(std_val, 1.0),
            min(min_val, 1.0),
            min(max_val, 1.0),
            min(cv, 1.0),
            burst_ratio,
            slow_ratio,
            abs(autocorr),
            regularity,
            density,
            min(jitter, 1.0),
            len(patterns) / 1000.0  # sample count indicator
        ]
        
    def _extract_memory_features(self, data: BehavioralData) -> List[float]:
        ops = data.memory_operations
        timeline = data.memory_timeline
        
        if not timeline or len(timeline) < 2:
            return [0.0] * 12
        
        arr = np.array(timeline, dtype=np.float64)
        
        # Memory growth rate (linear regression slope)
        x = np.arange(len(arr))
        if len(arr) > 1:
            slope = float(np.polyfit(x, arr, 1)[0])
        else:
            slope = 0.0
        
        # Normalize slope relative to mean memory
        mean_mem = float(np.mean(arr))
        growth_rate = slope / mean_mem if mean_mem > 0 else 0.0
        
        # Memory volatility (std/mean)
        mem_cv = float(np.std(arr)) / mean_mem if mean_mem > 0 else 0.0
        
        # Memory peak ratio (max/mean)
        peak_ratio = float(np.max(arr)) / mean_mem if mean_mem > 0 else 0.0
        
        # Memory trend (is memory increasing or stable?)
        first_half = float(np.mean(arr[:len(arr)//2]))
        second_half = float(np.mean(arr[len(arr)//2:]))
        trend = (second_half - first_half) / first_half if first_half > 0 else 0.0
        
        # Absolute memory usage (in MB, normalized)
        abs_mem_mb = mean_mem / (1024 * 1024)
        
        # Memory allocation pattern (sudden jumps)
        if len(arr) > 2:
            mem_diffs = np.diff(arr)
            jump_ratio = float(np.sum(np.abs(mem_diffs) > mean_mem * 0.1)) / len(mem_diffs)
        else:
            jump_ratio = 0.0
        
        # Samples count
        samples = ops.get('samples', 0)
        
        return [
            min(abs_mem_mb / 100.0, 1.0),  # absolute memory (normalized to 100MB)
            min(max(growth_rate, 0), 1.0),  # growth rate (clipped)
            min(mem_cv, 1.0),               # volatility
            min(peak_ratio / 2.0, 1.0),     # peak ratio
            min(max(trend, 0), 1.0),        # trend
            min(jump_ratio, 1.0),           # jump ratio
            samples / 100.0,                # sample count
            float(np.min(arr)) / (1024 * 1024 * 100),  # min mem MB
            float(np.max(arr)) / (1024 * 1024 * 100),  # max mem MB
            float(np.std(arr)) / (1024 * 1024),        # std in MB
            min(abs(growth_rate), 1.0),     # abs growth rate
            min(abs(trend), 1.0)            # abs trend
        ]
        
    def _extract_io_features(self, data: BehavioralData) -> List[float]:
        ops = data.io_operations
        timeline = data.io_timeline
        
        read_bytes = ops.get('read_bytes', 0)
        write_bytes = ops.get('write_bytes', 0)
        read_count = ops.get('read_count', 0)
        write_count = ops.get('write_count', 0)
        
        total_bytes = read_bytes + write_bytes
        total_count = read_count + write_count
        
        # Write ratio (malware tends to write more)
        write_ratio = write_bytes / total_bytes if total_bytes > 0 else 0.0
        
        # Write count ratio
        write_count_ratio = write_count / total_count if total_count > 0 else 0.0
        
        # Bytes per operation
        bytes_per_op = total_bytes / total_count if total_count > 0 else 0.0
        
        # I/O intensity (total bytes normalized)
        io_intensity = min(total_bytes / (1024 * 1024), 1.0)  # MB
        
        # I/O timeline features
        if timeline and len(timeline) > 1:
            io_arr = np.array(timeline, dtype=np.float64)
            io_cv = float(np.std(io_arr)) / float(np.mean(io_arr)) if np.mean(io_arr) > 0 else 0.0
            io_burst = float(np.max(io_arr)) / float(np.mean(io_arr)) if np.mean(io_arr) > 0 else 0.0
        else:
            io_cv = 0.0
            io_burst = 0.0
        
        return [
            write_ratio,
            write_count_ratio,
            min(bytes_per_op / 1024, 1.0),  # KB per operation
            io_intensity,
            min(read_bytes / (1024 * 1024), 1.0),
            min(write_bytes / (1024 * 1024), 1.0),
            min(read_count / 1000, 1.0),
            min(write_count / 1000, 1.0),
            min(io_cv, 1.0),
            min(io_burst / 10.0, 1.0),
            total_count / 10000.0,
            min(total_bytes / (10 * 1024 * 1024), 1.0)  # 10MB scale
        ]
        
    def _extract_network_features(self, data: BehavioralData) -> List[float]:
        ops = data.network_operations
        
        statuses = ['ESTABLISHED', 'LISTEN', 'TIME_WAIT', 'CLOSE_WAIT', 'SYN_SENT']
        values = [ops.get(s, 0) for s in statuses]
        total = sum(values) or 1
        
        # Connection diversity
        active_statuses = sum(1 for v in values if v > 0)
        diversity = active_statuses / len(statuses)
        
        # Suspicious connection patterns
        close_wait_ratio = ops.get('CLOSE_WAIT', 0) / total
        syn_sent_ratio = ops.get('SYN_SENT', 0) / total
        
        return [
            ops.get('ESTABLISHED', 0) / total,
            ops.get('LISTEN', 0) / total,
            ops.get('TIME_WAIT', 0) / total,
            close_wait_ratio,
            syn_sent_ratio,
            diversity,
            total / 100.0,
            0.0, 0.0, 0.0, 0.0, 0.0
        ]
        
    def _extract_file_features(self, data: BehavioralData) -> List[float]:
        ops = data.file_operations
        open_count = ops.get('open_files_count', 0)
        samples = ops.get('samples', 1)
        avg_open = open_count / samples if samples > 0 else 0.0
        
        return [
            min(avg_open / 10.0, 1.0),
            min(open_count / 1000.0, 1.0),
            0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0
        ]
        
    def _extract_process_features(self, data: BehavioralData) -> List[float]:
        ops = data.process_operations
        timeline = data.cpu_timeline
        
        cpu_total = ops.get('cpu_total', 0)
        cpu_samples = ops.get('cpu_samples', 1)
        cpu_avg = cpu_total / cpu_samples if cpu_samples > 0 else 0.0
        
        threads_max = ops.get('threads_max', 1)
        threads_total = ops.get('threads_total', 0)
        thread_avg = threads_total / cpu_samples if cpu_samples > 0 else 0.0
        
        # CPU volatility from timeline
        if timeline and len(timeline) > 1:
            cpu_arr = np.array(timeline)
            cpu_cv = float(np.std(cpu_arr)) / float(np.mean(cpu_arr)) if np.mean(cpu_arr) > 0 else 0.0
            cpu_max = float(np.max(cpu_arr))
            cpu_spikes = float(np.sum(cpu_arr > cpu_avg * 2)) / len(cpu_arr) if cpu_avg > 0 else 0.0
        else:
            cpu_cv = 0.0
            cpu_max = cpu_avg
            cpu_spikes = 0.0
        
        return [
            min(cpu_avg / 100.0, 1.0),
            min(cpu_max / 100.0, 1.0),
            min(cpu_cv, 1.0),
            cpu_spikes,
            min(threads_max / 10.0, 1.0),
            min(thread_avg / 5.0, 1.0),
            cpu_samples / 100.0,
            0.0, 0.0, 0.0, 0.0, 0.0
        ]
        
    def _extract_rhythm_features(self, data: BehavioralData) -> List[float]:
        """Extract behavioral rhythm - periodicity and cadence patterns"""
        patterns = data.timing_patterns
        bursts = data.burst_events
        
        if not patterns:
            return [0.0] * 12
        
        arr = np.array(patterns)
        
        # Rhythm regularity (how periodic is the behavior)
        if len(arr) > 20:
            # Check for periodicity via autocorrelation at multiple lags
            autocorrs = []
            for lag in [1, 5, 10, 20]:
                if len(arr) > lag * 2:
                    corr = float(np.corrcoef(arr[:-lag], arr[lag:])[0, 1])
                    if not np.isnan(corr):
                        autocorrs.append(abs(corr))
                    else:
                        autocorrs.append(0.0)
                else:
                    autocorrs.append(0.0)
        else:
            autocorrs = [0.0, 0.0, 0.0, 0.0]
        
        # Burst density
        burst_density = len(bursts) / max(len(patterns), 1)
        
        # Operation rhythm (sleep/work ratio)
        sleep_ratio = float(np.sum(arr > 0.05)) / len(arr)
        work_ratio = 1.0 - sleep_ratio
        
        # Cadence variance (how much the rhythm changes)
        if len(arr) > 10:
            windows = [arr[i:i+5] for i in range(0, len(arr)-5, 5)]
            window_means = [float(np.mean(w)) for w in windows]
            cadence_var = float(np.std(window_means)) / float(np.mean(window_means)) if np.mean(window_means) > 0 else 0.0
        else:
            cadence_var = 0.0
        
        return [
            autocorrs[0],   # lag-1 autocorrelation
            autocorrs[1],   # lag-5 autocorrelation
            autocorrs[2],   # lag-10 autocorrelation
            autocorrs[3],   # lag-20 autocorrelation
            min(burst_density, 1.0),
            sleep_ratio,
            work_ratio,
            min(cadence_var, 1.0),
            len(patterns) / 1000.0,
            min(len(bursts) / 50.0, 1.0),
            float(np.median(arr)),
            float(np.percentile(arr, 95))
        ]
        
    def _extract_entropy_features(self, data: BehavioralData) -> List[float]:
        """Extract entropy/randomness features from behavioral patterns"""
        patterns = data.timing_patterns
        mem_timeline = data.memory_timeline
        cpu_timeline = data.cpu_timeline
        io_timeline = data.io_timeline
        
        def calc_entropy(values):
            if not values or len(values) < 2:
                return 0.0
            arr = np.array(values, dtype=np.float64)
            arr = arr - np.min(arr)
            total = np.sum(arr)
            if total == 0:
                return 0.0
            probs = arr / total
            probs = probs[probs > 0]
            return float(-np.sum(probs * np.log2(probs)))
        
        def calc_uniformity(values):
            """How uniform/even the distribution is (0=uneven, 1=uniform)"""
            if not values or len(values) < 2:
                return 0.0
            arr = np.array(values, dtype=np.float64)
            arr = arr - np.min(arr)
            total = np.sum(arr)
            if total == 0:
                return 0.0
            probs = arr / total
            max_entropy = np.log2(len(probs))
            actual_entropy = float(-np.sum(probs[probs > 0] * np.log2(probs[probs > 0])))
            return float(actual_entropy / max_entropy) if max_entropy > 0 else 0.0
        
        timing_entropy = calc_entropy(patterns)
        mem_entropy = calc_entropy(mem_timeline)
        cpu_entropy = calc_entropy(cpu_timeline)
        io_entropy = calc_entropy(io_timeline)
        
        timing_uniformity = calc_uniformity(patterns)
        mem_uniformity = calc_uniformity(mem_timeline)
        
        return [
            min(timing_entropy / 10.0, 1.0),
            min(mem_entropy / 10.0, 1.0),
            min(cpu_entropy / 10.0, 1.0),
            min(io_entropy / 10.0, 1.0),
            timing_uniformity,
            mem_uniformity,
            0.0, 0.0, 0.0, 0.0, 0.0, 0.0
        ]
        
    def _compute_hash(self, data: Dict) -> str:
        json_str = json.dumps(data, sort_keys=True)
        return hashlib.sha256(json_str.encode()).hexdigest()


import time
