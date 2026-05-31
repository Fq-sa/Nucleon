"""
Behavioral Analyzer Module
محلل السلوك - يحلل سلوك البرنامج ويجمع البيانات السلوكية
"""
import psutil
import time
from typing import Dict, List, Optional
from dataclasses import dataclass, field
from collections import defaultdict
import threading
from utils.logger import logger


@dataclass
class BehavioralData:
    syscall_sequence: List[str] = field(default_factory=list)
    timing_patterns: List[float] = field(default_factory=list)
    memory_operations: Dict[str, int] = field(default_factory=dict)
    io_operations: Dict[str, int] = field(default_factory=dict)
    network_operations: Dict[str, int] = field(default_factory=dict)
    file_operations: Dict[str, int] = field(default_factory=dict)
    process_operations: Dict[str, int] = field(default_factory=dict)
    context_data: Dict[str, any] = field(default_factory=dict)
    memory_timeline: List[int] = field(default_factory=list)
    cpu_timeline: List[float] = field(default_factory=list)
    io_timeline: List[int] = field(default_factory=list)
    entropy_samples: List[float] = field(default_factory=list)
    burst_events: List[float] = field(default_factory=list)
    data_volume: int = 0


class BehaviorAnalyzer:
    def __init__(self, pid: int, timeout: int = 30):
        self.pid = pid
        self.timeout = timeout
        self.behavioral_data = BehavioralData()
        self.is_running = False
        self.monitor_thread = None
        
    def start_monitoring(self):
        logger.info(f"بدء مراقبة السلوك للعملية {self.pid}")
        self.is_running = True
        self.monitor_thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self.monitor_thread.start()
        
    def stop_monitoring(self):
        logger.info(f"إيقاف مراقبة السلوك للعملية {self.pid}")
        self.is_running = False
        if self.monitor_thread:
            self.monitor_thread.join(timeout=2)
            
    def _monitor_loop(self):
        start_time = time.time()
        last_check = start_time
        
        try:
            process = psutil.Process(self.pid)
        except psutil.NoSuchProcess:
            logger.error(f"العملية {self.pid} غير موجودة")
            return
            
        while self.is_running and (time.time() - start_time) < self.timeout:
            try:
                current_time = time.time()
                time_delta = current_time - last_check
                
                self._collect_memory_stats(process)
                self._collect_io_stats(process)
                self._collect_network_stats(process)
                self._collect_file_stats(process)
                self._collect_process_stats(process)
                self._collect_timing_pattern(time_delta)
                
                last_check = current_time
                time.sleep(0.1)
                
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                logger.warning(f"تم فقدان الوصول للعملية {self.pid}")
                break
                
    def _collect_memory_stats(self, process: psutil.Process):
        try:
            mem_info = process.memory_info()
            self.behavioral_data.memory_operations['rss_total'] = (
                self.behavioral_data.memory_operations.get('rss_total', 0) + mem_info.rss
            )
            self.behavioral_data.memory_operations['vms_total'] = (
                self.behavioral_data.memory_operations.get('vms_total', 0) + mem_info.vms
            )
            self.behavioral_data.memory_operations['samples'] = (
                self.behavioral_data.memory_operations.get('samples', 0) + 1
            )
            self.behavioral_data.memory_timeline.append(mem_info.rss)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
            
    def _collect_io_stats(self, process: psutil.Process):
        try:
            if hasattr(process, 'io_counters'):
                io_info = process.io_counters()
                self.behavioral_data.io_operations['read_bytes'] = (
                    self.behavioral_data.io_operations.get('read_bytes', 0) + io_info.read_bytes
                )
                self.behavioral_data.io_operations['write_bytes'] = (
                    self.behavioral_data.io_operations.get('write_bytes', 0) + io_info.write_bytes
                )
                self.behavioral_data.io_operations['read_count'] = (
                    self.behavioral_data.io_operations.get('read_count', 0) + io_info.read_count
                )
                self.behavioral_data.io_operations['write_count'] = (
                    self.behavioral_data.io_operations.get('write_count', 0) + io_info.write_count
                )
                self.behavioral_data.io_timeline.append(io_info.read_bytes + io_info.write_bytes)
        except (psutil.NoSuchProcess, psutil.AccessDenied, AttributeError):
            pass
            
    def _collect_network_stats(self, process: psutil.Process):
        try:
            connections = process.connections()
            for conn in connections:
                status = conn.status
                self.behavioral_data.network_operations[status] = (
                    self.behavioral_data.network_operations.get(status, 0) + 1
                )
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
            
    def _collect_file_stats(self, process: psutil.Process):
        try:
            open_files = process.open_files()
            self.behavioral_data.file_operations['open_files_count'] = (
                self.behavioral_data.file_operations.get('open_files_count', 0) + len(open_files)
            )
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
            
    def _collect_process_stats(self, process: psutil.Process):
        try:
            cpu_percent = process.cpu_percent()
            self.behavioral_data.process_operations['cpu_total'] = (
                self.behavioral_data.process_operations.get('cpu_total', 0) + cpu_percent
            )
            self.behavioral_data.process_operations['cpu_samples'] = (
                self.behavioral_data.process_operations.get('cpu_samples', 0) + 1
            )
            self.behavioral_data.cpu_timeline.append(cpu_percent)
            
            # Track data volume through thread count and children
            num_threads = process.num_threads()
            self.behavioral_data.process_operations['threads_total'] = (
                self.behavioral_data.process_operations.get('threads_total', 0) + num_threads
            )
            self.behavioral_data.process_operations['threads_max'] = max(
                self.behavioral_data.process_operations.get('threads_max', 0), num_threads
            )
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
            
    def _collect_timing_pattern(self, time_delta: float):
        self.behavioral_data.timing_patterns.append(time_delta)
        
        # Detect burst events (sudden activity spikes)
        if len(self.behavioral_data.timing_patterns) > 10:
            recent_avg = sum(self.behavioral_data.timing_patterns[-10:]) / 10
            if time_delta < recent_avg * 0.3:  # Much faster than recent average
                self.behavioral_data.burst_events.append(time.time())
        
    def get_behavioral_data(self) -> BehavioralData:
        return self.behavioral_data
