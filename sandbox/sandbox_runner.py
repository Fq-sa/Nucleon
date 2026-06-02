"""
Sandbox Isolation Engine v4.0
محرك العزل والتحليل الآمن للعينات الخبيثة

Academic Research: Process-level sandbox with resource monitoring
يدعم عزل العمليات ومراقبتها بدون التأثير على النظام المضيف
"""

import os
import sys
import time
import json
import signal
import psutil
import tempfile
import subprocess
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum

sys.path.insert(0, str(Path(__file__).parent.parent))
from utils.logger import logger


class SandboxMode(Enum):
    """Sandbox operational modes"""
    PROCESS = "process"         # Process-level isolation
    CHROOT = "chroot"           # Chroot jail
    BUBBLEWRAP = "bubblewrap"  # Linux bubblewrap
    DOCKER = "docker"           # Docker container
    FIREJAIL = "firejail"       # Firejail sandbox


@dataclass
class SandboxConfig:
    """Sandbox configuration"""
    mode: SandboxMode = SandboxMode.PROCESS
    timeout: int = 30           # Max execution time
    max_memory_mb: int = 512    # Max memory
    max_cpu_percent: int = 50   # Max CPU usage
    max_disk_mb: int = 100      # Max disk writes
    network_enabled: bool = False  # Allow network access
    filesystem_access: bool = True  # Allow filesystem access
    allowed_paths: List[str] = field(default_factory=list)
    denied_paths: List[str] = field(default_factory=list)
    monitor_children: bool = True
    kill_on_timeout: bool = True


@dataclass
class SandboxResult:
    """Sandbox execution result"""
    success: bool = False
    exit_code: int = 0
    duration: float = 0.0
    stdout: str = ""
    stderr: str = ""
    
    # Resource metrics
    cpu_usage_percent: float = 0.0
    memory_peak_mb: float = 0.0
    memory_avg_mb: float = 0.0
    disk_read_mb: float = 0.0
    disk_write_mb: float = 0.0
    network_sent_mb: float = 0.0
    network_recv_mb: float = 0.0
    
    # Process tree
    processes_spawned: int = 0
    child_processes: List[int] = field(default_factory=list)
    
    # Behavioral flags
    created_files: List[str] = field(default_factory=list)
    deleted_files: List[str] = field(default_factory=list)
    modified_registry: List[str] = field(default_factory=list)
    network_connections: List[Dict] = field(default_factory=list)
    
    # Verdict
    verdict: str = "CLEAN"
    threat_score: float = 0.0
    threat_flags: List[str] = field(default_factory=list)
    
    # Anomalies
    anomalies: List[str] = field(default_factory=list)
    
    error: str = ""


class SandboxRunner:
    """
    Process sandbox for safe malware execution
    Implements resource limits and behavioral monitoring
    """
    
    def __init__(self, config: Optional[SandboxConfig] = None):
        self.config = config or SandboxConfig()
        self._temp_dir = None
        self._log_file = None
    
    def _setup_environment(self) -> Path:
        """Setup isolated environment"""
        self._temp_dir = Path(tempfile.mkdtemp(prefix="nucleon_sandbox_"))
        
        # Create workspace
        workspace = self._temp_dir / "workspace"
        workspace.mkdir(exist_ok=True)
        
        logger.info(f"تم إعداد بيئة العزل: {self._temp_dir}")
        return workspace
    
    def _cleanup_environment(self):
        """Cleanup sandbox environment"""
        import shutil
        if self._temp_dir and self._temp_dir.exists():
            try:
                shutil.rmtree(self._temp_dir)
                logger.info(f"تم تنظيف بيئة العزل: {self._temp_dir}")
            except Exception as e:
                logger.warning(f"خطأ في تنظيف بيئة العزل: {e}")
    
    def run_script(self, script_path: Path, args: List[str] = None) -> SandboxResult:
        """
        Run a Python script in sandboxed environment
        Returns detailed SandboxResult
        """
        logger.info(f"تشغيل script في الـ sandbox: {script_path}")
        result = SandboxResult()
        
        workspace = self._setup_environment()
        
        try:
            # Copy script to workspace
            import shutil
            dest = workspace / script_path.name
            shutil.copy2(script_path, dest)
            
            # Start process
            start_time = time.time()
            cmd = [sys.executable, str(dest)]
            if args:
                cmd.extend(args)
            
            # Environment isolation
            env = os.environ.copy()
            env['HOME'] = str(workspace)
            env['TMPDIR'] = str(self._temp_dir)
            env['TEMP'] = str(self._temp_dir)
            env['TMP'] = str(self._temp_dir)
            env['PYTHONPATH'] = ''
            
            # Resource limits
            try:
                import resource
                # Soft limit
                resource.setrlimit(
                    resource.RLIMIT_CPU,
                    (self.config.timeout, self.config.timeout)
                )
                resource.setrlimit(
                    resource.RLIMIT_AS,
                    (self.config.max_memory_mb * 1024 * 1024,
                     self.config.max_memory_mb * 1024 * 1024)
                )
            except (ImportError, ValueError):
                pass  # resource module not available on all platforms
            
            proc = subprocess.Popen(
                cmd,
                cwd=str(workspace),
                env=env,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            
            # Monitor process
            result = self._monitor_process(proc, result, start_time)
            
            # Wait for completion or timeout
            try:
                stdout, stderr = proc.communicate(timeout=self.config.timeout)
                result.stdout = stdout
                result.stderr = stderr
                result.exit_code = proc.returncode
                result.success = True
            except subprocess.TimeoutExpired:
                logger.warning(f"انتهت مهلة الـ sandbox ({self.config.timeout}s)")
                result.anomalies.append("timeout_expired")
                
                if self.config.kill_on_timeout:
                    self._kill_process_tree(proc.pid)
                
                try:
                    stdout, stderr = proc.communicate(timeout=5)
                    result.stdout = stdout or ""
                    result.stderr = stderr or ""
                except:
                    pass
            
            result.duration = time.time() - start_time
            
            # Analyze behavior
            self._analyze_behavior(result, workspace)
            
            # Generate verdict
            self._compute_verdict(result)
            
        except Exception as e:
            logger.error(f"خطأ في Sandbox: {e}")
            result.error = str(e)
            result.success = False
        
        finally:
            # Give time for mitigation report
            time.sleep(0.5)
            self._cleanup_environment()
        
        return result
    
    def _monitor_process(self, proc: subprocess.Popen, result: SandboxResult, start_time: float) -> SandboxResult:
        """Monitor process resources"""
        try:
            ps_proc = psutil.Process(proc.pid)
            cpu_samples = []
            mem_samples = []
            io_start = None
            
            try:
                io_start = ps_proc.io_counters()
            except:
                pass
            
            while proc.poll() is None:
                try:
                    cpu = ps_proc.cpu_percent(interval=0.1)
                    mem = ps_proc.memory_info()
                    
                    cpu_samples.append(cpu)
                    mem_samples.append(mem.rss / (1024 * 1024))
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    break
                
                time.sleep(0.2)
            
            # Compute averages
            if cpu_samples:
                result.cpu_usage_percent = sum(cpu_samples) / len(cpu_samples)
            if mem_samples:
                result.memory_peak_mb = max(mem_samples)
                result.memory_avg_mb = sum(mem_samples) / len(mem_samples)
            
            # IO accounting
            try:
                io_end = ps_proc.io_counters()
                if io_start and io_end:
                    result.disk_read_mb = (
                        (io_end.read_bytes - io_start.read_bytes) / (1024 * 1024)
                    )
                    result.disk_write_mb = (
                        (io_end.write_bytes - io_start.write_bytes) / (1024 * 1024)
                    )
            except:
                pass
            
            # Monitor children
            if self.config.monitor_children:
                try:
                    children = ps_proc.children(recursive=True)
                    result.processes_spawned = len(children)
                    result.child_processes = [c.pid for c in children]
                except:
                    pass
            
            # Network connections
            try:
                conns = ps_proc.connections()
                for conn in conns:
                    result.network_connections.append({
                        'fd': conn.fd,
                        'family': str(conn.family),
                        'type': str(conn.type),
                        'laddr': f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else "",
                        'raddr': f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else "",
                        'status': conn.status,
                    })
            except:
                pass
        
        except psutil.NoSuchProcess:
            pass
        
        return result
    
    def _kill_process_tree(self, pid: int):
        """Kill process and all children"""
        try:
            parent = psutil.Process(pid)
            children = parent.children(recursive=True)
            for child in children:
                try:
                    child.kill()
                except:
                    pass
            parent.kill()
        except:
            pass
    
    def _analyze_behavior(self, result: SandboxResult, workspace: Path):
        """Analyze sandbox behavior for anomalies"""
        
        # Check CPU usage
        if result.cpu_usage_percent > 80:
            result.anomalies.append(f"high_cpu: {result.cpu_usage_percent:.1f}%")
            result.threat_flags.append("CPU_HOG")
        
        # Check memory usage
        if result.memory_peak_mb > 200:
            result.anomalies.append(f"high_memory: {result.memory_peak_mb:.1f}MB")
            result.threat_flags.append("MEMORY_HOG")
        
        # Check for child processes
        if result.processes_spawned > 3:
            result.anomalies.append(f"children_spawned: {result.processes_spawned}")
            result.threat_flags.append("PROCESS_SPAWNING")
        
        # Check for network activity
        if result.network_connections:
            result.anomalies.append(f"network_connections: {len(result.network_connections)}")
            result.threat_flags.append("NETWORK_ACCESS")
        
        # Check disk writes
        if result.disk_write_mb > 10:
            result.anomalies.append(f"disk_write: {result.disk_write_mb:.1f}MB")
        
        # Check stdout/stderr for errors
        stderr_lower = result.stderr.lower()
        error_indicators = [
            'error', 'exception', 'traceback', 'failed',
            'permission denied', 'access denied',
        ]
        for indicator in error_indicators:
            if indicator in stderr_lower:
                result.anomalies.append(f"runtime_error: {indicator}")
                break
        
        # Check created files in workspace
        workspace_files = list(workspace.rglob('*')) if workspace else []
        for f in workspace_files:
            if f.is_file() and f.name != script_path.name if hasattr(self, '_script_name') else True:
                result.created_files.append(str(f))
        
        if len(result.created_files) > 5:
            result.anomalies.append(f"many_files_created: {len(result.created_files)}")
            result.threat_flags.append("FILE_CREATION")
    
    def _compute_verdict(self, result: SandboxResult):
        """Compute malware verdict from behavior"""
        score = 0.0
        
        # Score CPU anomalies
        if result.cpu_usage_percent > 80:
            score += 15
        elif result.cpu_usage_percent > 50:
            score += 8
        
        # Score memory anomalies
        if result.memory_peak_mb > 300:
            score += 20
        elif result.memory_peak_mb > 100:
            score += 10
        
        # Score process spawning
        score += min(result.processes_spawned * 8, 30)
        
        # Score network access
        score += min(len(result.network_connections) * 5, 25)
        
        # Score disk writes
        if result.disk_write_mb > 50:
            score += 20
        elif result.disk_write_mb > 10:
            score += 10
        
        result.threat_score = min(score, 100)
        
        if result.threat_score >= 50:
            result.verdict = "MALICIOUS"
        elif result.threat_score >= 25:
            result.verdict = "SUSPICIOUS"
        else:
            result.verdict = "CLEAN"


class DockerSandbox(SandboxRunner):
    """Docker-based sandbox for stronger isolation"""
    
    def __init__(self, config: Optional[SandboxConfig] = None):
        super().__init__(config)
        self.config.mode = SandboxMode.DOCKER
    
    def run_in_container(self, script_path: Path, image: str = "python:3.11-slim") -> SandboxResult:
        """Run script inside Docker container"""
        result = SandboxResult()
        
        try:
            # Check Docker availability
            check = subprocess.run(
                ["docker", "version", "--format", "{{.Server.Version}}"],
                capture_output=True, text=True, timeout=5
            )
            if check.returncode != 0:
                result.error = "Docker not available"
                return result
            
            start_time = time.time()
            
            script_dir = script_path.parent
            script_name = script_path.name
            
            # Build Docker command
            cmd = [
                "docker", "run", "--rm",
                "--network", "none" if not self.config.network_enabled else "bridge",
                "--memory", f"{self.config.max_memory_mb}m",
                "--cpus", "1",
                "--timeout", str(self.config.timeout),
                "-v", f"{script_dir}:/sandbox:ro",
                "-w", "/sandbox",
                image,
                "python", f"/sandbox/{script_name}",
            ]
            
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.config.timeout + 10,
            )
            
            result.stdout = proc.stdout
            result.stderr = proc.stderr
            result.exit_code = proc.returncode
            result.duration = time.time() - start_time
            result.success = proc.returncode == 0
            
            if result.stderr:
                stderr_lower = result.stderr.lower()
                if 'error' in stderr_lower or 'exception' in stderr_lower:
                    result.anomalies.append("container_errors")
            
            self._compute_verdict(result)
            
        except subprocess.TimeoutExpired:
            result.anomalies.append("docker_timeout")
            result.error = "Container timeout"
        except FileNotFoundError:
            result.error = "Docker not installed"
        except Exception as e:
            result.error = str(e)
        
        return result


def main():
    """CLI entry point for sandbox"""
    import argparse
    
    parser = argparse.ArgumentParser(description="Nucleon Sandbox Runner")
    parser.add_argument("script", help="Path to script to sandbox")
    parser.add_argument("--timeout", type=int, default=30, help="Execution timeout")
    parser.add_argument("--mode", choices=["process", "docker"], default="process")
    parser.add_argument("--network", action="store_true", help="Allow network access")
    
    args = parser.parse_args()
    
    config = SandboxConfig(
        timeout=args.timeout,
        network_enabled=args.network,
    )
    
    if args.mode == "docker":
        sandbox = DockerSandbox(config)
        result = sandbox.run_in_container(Path(args.script))
    else:
        sandbox = SandboxRunner(config)
        result = sandbox.run_script(Path(args.script))
    
    # Print results
    print(f"\n{'='*60}")
    print(f"  Nucleon Sandbox Results")
    print(f"{'='*60}")
    print(f"  Verdict:      {result.verdict}")
    print(f"  Threat Score: {result.threat_score:.1f}")
    print(f"  Duration:     {result.duration:.2f}s")
    print(f"  CPU Avg:      {result.cpu_usage_percent:.1f}%")
    print(f"  Memory Peak:  {result.memory_peak_mb:.1f}MB")
    print(f"  Children:     {result.processes_spawned}")
    print(f"  Network:      {len(result.network_connections)} conns")
    print(f"  Disk Write:   {result.disk_write_mb:.1f}MB")
    if result.anomalies:
        print(f"\n  Anomalies:")
        for a in result.anomalies:
            print(f"    - {a}")
    if result.error:
        print(f"\n  Error: {result.error}")
    print(f"{'='*60}\n")


if __name__ == "__main__":
    main()
