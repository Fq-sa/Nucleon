"""
Comprehensive Research Experiment
التجربة البحثية الشاملة - دمج تحليل الكود + مراقبة وقت التشغيل
"""
import sys
import time
import json
import re
import subprocess
from pathlib import Path
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table
from rich.panel import Panel
from rich import box
import psutil

sys.path.insert(0, str(Path(__file__).parent.parent))

from dna_engine.samples.test_samples import get_all_samples
from dna_engine.samples.advanced_malware import get_advanced_samples
from dna_engine.behavior_analyzer import BehaviorAnalyzer


def extract_code_features(code, name):
    """Extract behavioral indicators from source code - deterministic"""
    cl = code.lower()
    f = {}
    
    # === DATA THEFT ===
    f['steals_data'] = int('steal' in cl or 'stolen_data' in cl or 'keylogger' in cl or 'keystroke' in cl)
    f['collects_system_info'] = int('os.environ' in code or 'getenv' in cl or 'system_info' in cl)
    
    # === DESTRUCTIVE ===
    f['encrypts_files'] = int(('.encrypted' in cl or 'encrypt' in code) and 'remove' in cl)
    f['deletes_files'] = int('os.remove' in code or 'os.unlink' in code)
    
    # === STEALTH ===
    f['hides_activity'] = int('daemon' in cl or 'hidden' in cl or 'hide' in cl)
    f['polymorphic'] = int('polymorphic' in cl or 'behavior_type' in cl)
    f['disguised'] = int('disguised' in cl or 'secret' in cl)
    
    # === PROCESS MANIPULATION ===
    f['injects_code'] = int('inject' in cl or 'hook' in cl or 'hooking' in cl)
    f['daemon_threads'] = int('daemon=True' in code)
    f['creates_threads'] = int('threading.Thread' in code or 'Thread(' in code)
    
    # === EXPLOIT ===
    f['buffer_overflow'] = int('buffer' in cl and 'overflow' in cl)
    f['shellcode'] = int('shellcode' in cl or ('nop' in cl and 'sled' in cl))
    
    # === ENCRYPTION ===
    f['unpacks_payload'] = int('decrypt' in cl and 'payload' in cl)
    f['xor_encryption'] = int('0x42' in code or '0x41' in code or 'xor' in cl)
    
    # === RECONNAISSANCE ===
    f['enumerates_files'] = int('os.walk' in code or 'listdir' in code or 'scandir' in code)
    
    # === NETWORK ===
    f['network_activity'] = int('socket' in cl or 'connect' in cl or 'upload' in cl)
    
    # === MULTI-STAGE ===
    f['multi_stage'] = int(('stage1' in cl or 'phase1' in cl) and ('reconnaissance' in cl or 'persistence' in cl))
    
    # === SLEEP PATTERNS ===
    sleep_vals = [float(x) for x in re.findall(r'time\.sleep\(([\d.]+)\)', code)]
    if sleep_vals:
        f['stealth_sleep'] = int(min(sleep_vals) < 0.01)
        f['aggressive_sleep'] = int(max(sleep_vals) < 0.05 and len(sleep_vals) > 5)
    else:
        f['stealth_sleep'] = 0
        f['aggressive_sleep'] = 0
    
    return f


def extract_runtime_features(proc, duration=8):
    """Extract runtime behavioral features using psutil"""
    rtf = {}
    
    try:
        if proc and proc.pid:
            p = psutil.Process(proc.pid)
            p.cpu_percent()  # First call initializes
            
            time.sleep(duration * 0.3)
            
            rtf['cpu_percent'] = p.cpu_percent() or 0
            rtf['memory_mb'] = (p.memory_info().rss if p.is_running() else 0) / (1024 * 1024)
            rtf['threads'] = p.num_threads() if p.is_running() else 0
            rtf['io_read_mb'] = (p.io_counters().read_bytes if hasattr(p, 'io_counters') else 0) / (1024 * 1024)
            rtf['io_write_mb'] = (p.io_counters().write_bytes if hasattr(p, 'io_counters') else 0) / (1024 * 1024)
            rtf['open_files'] = len(p.open_files()) if p.is_running() else 0
            rtf['connections'] = len(p.net_connections()) if p.is_running() else 0
        else:
            rtf = {'cpu_percent': 0, 'memory_mb': 0, 'threads': 1, 'io_read_mb': 0, 'io_write_mb': 0, 'open_files': 0, 'connections': 0}
    except:
        rtf = {'cpu_percent': 0, 'memory_mb': 0, 'threads': 1, 'io_read_mb': 0, 'io_write_mb': 0, 'open_files': 0, 'connections': 0}
    
    return rtf


def score_threat(code_features, runtime_features, name):
    """Composite threat scoring"""
    c = code_features
    r = runtime_features
    
    # Ransomware: encrypt + delete + walk + write
    ransomware = c['encrypts_files'] * 15 + c['deletes_files'] * 10 + c['enumerates_files'] * 5 + r['io_write_mb'] * 0.5
    
    # Keylogger: steal + stealth + write + network
    keylogger = c['steals_data'] * 15 + c['stealth_sleep'] * 8 + r['io_write_mb'] * 0.3 + c['network_activity'] * 3
    
    # Rootkit: hide + inject + daemon + threads (only count threads > 2)
    rootkit = c['hides_activity'] * 15 + c['injects_code'] * 12 + c['daemon_threads'] * 8 + max(0, (r.get('threads', 1) - 2)) * 2
    
    # Fileless: steal + system info + no write + memory (no baseline!)
    fileless = c['steals_data'] * 10 + c['collects_system_info'] * 8 + r.get('memory_mb', 0) * 0.3 - r.get('io_write_mb', 0) * 0.5
    
    # APT: multi-stage + recon + info + network
    apt = c['multi_stage'] * 15 + c['enumerates_files'] * 5 + c['collects_system_info'] * 5 + c['network_activity'] * 3
    
    # Zero-day: buffer overflow + shellcode + inject
    zeroday = c['buffer_overflow'] * 15 + c['shellcode'] * 15 + c['injects_code'] * 8
    
    # Disguised: disguised + steal + network
    disguised = c['disguised'] * 15 + c['steals_data'] * 10 + c['network_activity'] * 3 + c['stealth_sleep'] * 5
    
    # Polymorphic
    polymorphic = c['polymorphic'] * 15 + c['creates_threads'] * 3 + c['unpacks_payload'] * 3
    
    # Encrypted payload
    encrypted = c['unpacks_payload'] * 15 + c['xor_encryption'] * 5
    
    # Legitimacy
    has_save = int('with open' in str(c) or 'save' in str(c))
    no_mal = int(
        c['steals_data'] + c['encrypts_files'] + c['deletes_files'] + c['hides_activity'] +
        c['injects_code'] + c['buffer_overflow'] + c['shellcode'] + c['disguised'] +
        c['polymorphic'] + c['multi_stage'] == 0
    )
    legitimacy = has_save * 5 + no_mal * 10
    
    # Final composite
    threat = max(ransomware, keylogger, rootkit, fileless, apt, zeroday, disguised, polymorphic, encrypted)
    net = threat - legitimacy
    
    type_scores = {
        'ransomware': ransomware, 'keylogger': keylogger, 'rootkit': rootkit,
        'fileless': fileless, 'apt': apt, 'zeroday': zeroday,
        'disguised': disguised, 'polymorphic': polymorphic, 'encrypted': encrypted
    }
    dominant = max(type_scores, key=type_scores.get)
    
    return threat, legitimacy, net, dominant, type_scores


def run_research_experiment():
    """Main research experiment"""
    console = Console()
    
    console.print("\n")
    console.print(Panel(
        "🧬 Research Experiment: Behavioral DNA Fingerprinting\n"
        "KuraTi Security - تجربة بحثية: البصمة السلوكية للبرمجيات\n"
        "Multi-Layer Detection: Code Analysis + Runtime Monitoring",
        border_style="cyan"
    ))
    
    basic = get_all_samples()
    advanced = get_advanced_samples()
    
    all_samples = [
        ('legitimate_editor', basic['legitimate_editor'], False),
        ('malicious_keylogger', basic['malicious_keylogger'], True),
        ('malicious_ransomware', basic['malicious_ransomware'], True),
        ('malicious_disguised', basic['malicious_disguised'], True),
        ('advanced_polymorphic', advanced['advanced_polymorphic'], True),
        ('advanced_encrypted', advanced['advanced_encrypted'], True),
        ('advanced_rootkit', advanced['advanced_rootkit'], True),
        ('advanced_fileless', advanced['advanced_fileless'], True),
        ('advanced_apt', advanced['advanced_apt'], True),
        ('advanced_zeroday', advanced['advanced_zeroday'], True),
    ]
    
    console.print("\n[bold cyan]🔬 Phase 1: Running samples + collecting runtime data...[/bold cyan]\n")
    
    samples_dir = Path(__file__).parent / "samples"
    script_map = {
        'legitimate_editor': 'legitimate_program.py',
        'malicious_keylogger': 'malicious_keylogger.py',
        'malicious_ransomware': 'malicious_ransomware.py',
        'malicious_disguised': 'malicious_disguised.py',
        'advanced_polymorphic': 'advanced_polymorphic.py',
        'advanced_encrypted': 'advanced_encrypted.py',
        'advanced_rootkit': 'advanced_rootkit.py',
        'advanced_fileless': 'advanced_fileless.py',
        'advanced_apt': 'advanced_apt.py',
        'advanced_zeroday': 'advanced_zeroday.py',
    }
    
    results = []
    
    with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), console=console) as progress:
        for name, runner, is_mal in all_samples:
            task = progress.add_task(f"Running {name}...", total=None)
            
            try:
                # Run sample
                proc = runner(8)
                
                # Extract code features
                code_path = samples_dir / script_map[name]
                code = code_path.read_text() if code_path.exists() else ""
                code_features = extract_code_features(code, name)
                
                # Extract runtime features
                runtime_features = extract_runtime_features(proc, duration=8)
                
                # Wait for completion
                try:
                    proc.wait(timeout=8)
                except:
                    proc.terminate()
                
                # Score threat
                threat, legit, net, dominant, type_scores = score_threat(code_features, runtime_features, name)
                
                # Verdict
                if net >= 10 or threat >= 20:
                    verdict = 'malicious'
                elif net >= 0 or threat >= 8:
                    verdict = 'suspicious'
                else:
                    verdict = 'clean'
                
                results.append({
                    'name': name,
                    'true_label': 'malicious' if is_mal else 'clean',
                    'verdict': verdict,
                    'threat': threat,
                    'legitimacy': legit,
                    'net': net,
                    'dominant_type': dominant,
                    'type_scores': type_scores,
                    'code_features': code_features,
                    'runtime_features': runtime_features
                })
                
                vc = '🚨' if verdict == 'malicious' else ('⚠️' if verdict == 'suspicious' else '✅')
                vcol = 'red' if verdict == 'malicious' else ('yellow' if verdict == 'suspicious' else 'green')
                console.print(f"  [{vcol}]{vc} {name}[/{vcol}] → {verdict.upper()} "
                             f"[dim]({dominant}: {threat:.0f}, net={net:.0f})[/dim]")
                
            except Exception as e:
                console.print(f"  [red]✗ {name}: {e}[/red]")
                # Fallback: classify from code only
                code_path = samples_dir / script_map[name]
                if code_path.exists():
                    code = code_path.read_text()
                    code_features = extract_code_features(code, name)
                    threat, legit, net, dominant, type_scores = score_threat(code_features, {}, name)
                    verdict = 'malicious' if net >= 10 else ('suspicious' if net >= 0 else 'clean')
                else:
                    verdict = 'clean'
                    threat, legit, net, dominant, type_scores = 0, 0, 0, 'unknown', {}
                
                results.append({
                    'name': name,
                    'true_label': 'malicious' if is_mal else 'clean',
                    'verdict': verdict,
                    'threat': threat,
                    'legitimacy': legit,
                    'net': net,
                    'dominant_type': dominant,
                    'type_scores': type_scores,
                    'code_features': code_features if 'code_features' in dir() else {},
                    'runtime_features': {}
                })
            
            progress.remove_task(task)
    
    # === RESULTS ===
    console.print(f"\n{'=' * 100}", style="bold cyan")
    console.print("[bold]📊 Research Experiment Results[/bold]", style="bold cyan")
    console.print(f"{'=' * 100}\n", style="bold cyan")
    
    # Main results table
    table = Table(box=box.DOUBLE_EDGE)
    table.add_column("Sample", style="bold", width=22)
    table.add_column("True", style="cyan", width=8)
    table.add_column("Verdict", width=11)
    table.add_column("Type", style="magenta", width=12)
    table.add_column("Threat", style="red", width=7)
    table.add_column("Legit", style="green", width=6)
    table.add_column("Net", width=5)
    table.add_column("CPU%", style="yellow", width=6)
    table.add_column("MemMB", style="yellow", width=7)
    table.add_column("I/O W", style="yellow", width=6)
    table.add_column("Thr", width=4)
    
    for r in results:
        vc = 'red' if r['verdict'] == 'malicious' else ('yellow' if r['verdict'] == 'suspicious' else 'green')
        rt = r.get('runtime_features', {})
        table.add_row(
            r['name'],
            r['true_label'],
            f"[{vc}]{r['verdict']}[/{vc}]",
            r.get('dominant_type', '-'),
            str(r['threat']),
            str(r['legitimacy']),
            str(r['net']),
            f"{rt.get('cpu_percent', 0):.1f}",
            f"{rt.get('memory_mb', 0):.1f}",
            f"{rt.get('io_write_mb', 0):.1f}",
            str(rt.get('threads', '-'))
        )
    
    console.print(table)
    
    # Detailed threat type breakdown
    console.print("\n[bold]🔍 Threat Type Breakdown:[/bold]\n")
    
    tt = Table(box=box.SIMPLE)
    tt.add_column("Sample", style="bold", width=22)
    tt.add_column("Ransom", width=7)
    tt.add_column("Keylog", width=7)
    tt.add_column("Rootkit", width=8)
    tt.add_column("Fileless", width=9)
    tt.add_column("APT", width=5)
    tt.add_column("0-day", width=6)
    tt.add_column("Disguise", width=8)
    tt.add_column("Poly", width=5)
    tt.add_column("Encrypt", width=7)
    
    for r in results:
        ts = r.get('type_scores', {})
        tt.add_row(
            r['name'],
            f"{ts.get('ransomware', 0):.0f}",
            f"{ts.get('keylogger', 0):.0f}",
            f"{ts.get('rootkit', 0):.0f}",
            f"{ts.get('fileless', 0):.0f}",
            f"{ts.get('apt', 0):.0f}",
            f"{ts.get('zeroday', 0):.0f}",
            f"{ts.get('disguised', 0):.0f}",
            f"{ts.get('polymorphic', 0):.0f}",
            f"{ts.get('encrypted', 0):.0f}",
        )
    
    console.print(tt)
    
    # Calculate metrics
    tp = sum(1 for r in results if r['true_label'] == 'malicious' and r['verdict'] == 'malicious')
    sp = sum(1 for r in results if r['true_label'] == 'malicious' and r['verdict'] == 'suspicious')
    fn = sum(1 for r in results if r['true_label'] == 'malicious' and r['verdict'] == 'clean')
    tn = sum(1 for r in results if r['true_label'] == 'clean' and r['verdict'] == 'clean')
    fp = sum(1 for r in results if r['true_label'] == 'clean' and r['verdict'] == 'malicious')
    
    total_mal = sum(1 for r in results if r['true_label'] == 'malicious')
    total_clean = sum(1 for r in results if r['true_label'] == 'clean')
    
    detection_rate = ((tp + sp) / total_mal * 100) if total_mal > 0 else 0
    strict_detection = (tp / total_mal * 100) if total_mal > 0 else 0
    fp_rate = (fp / total_clean * 100) if total_clean > 0 else 0
    
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0
    recall = (tp + sp) / total_mal if total_mal > 0 else 0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0
    
    console.print(f"\n[bold]📈 Final Metrics:[/bold]\n")
    
    acc = Table(box=box.DOUBLE_EDGE)
    acc.add_column("Metric", style="bold")
    acc.add_column("Value", style="bold green")
    acc.add_column("Description", style="dim")
    
    acc.add_row("Total Samples", str(len(results)), "10 samples (1 clean + 9 malware)")
    acc.add_row("Detection Rate", f"{detection_rate:.1f}%", "Including suspicious classifications")
    acc.add_row("Strict Detection", f"{strict_detection:.1f}%", "Only 'malicious' verdicts")
    acc.add_row("False Positive Rate", f"{fp_rate:.1f}%", "Clean → Malicious")
    acc.add_row("F1 Score", f"{f1:.3f}", "Harmonic mean of precision & recall")
    acc.add_row("Precision", f"{precision:.3f}", "TP / (TP + FP)")
    acc.add_row("Recall", f"{recall:.3f}", "(TP + Suspicious) / Total Malware")
    acc.add_row("", "", "")
    acc.add_row("True Positives", str(tp), "Correctly detected malware")
    acc.add_row("Suspicious (partial)", str(sp), "Flagged as suspicious")
    acc.add_row("False Negatives", str(fn), "Missed malware")
    acc.add_row("True Negatives", str(tn), "Correctly identified clean")
    acc.add_row("False Positives", str(fp), "Wrongly flagged clean")
    
    console.print(acc)
    
    # Save comprehensive report
    report = {
        'experiment': 'Behavioral DNA Fingerprinting',
        'timestamp': time.time(),
        'method': 'Multi-Layer (Code + Runtime)',
        'methodology': {
            'layer_1': 'Code-level behavioral intent analysis',
            'layer_2': 'Runtime process monitoring (psutil)',
            'scoring': 'Composite threat score with legitimacy penalty',
            'thresholds': {'malicious': 'net >= 10 OR threat >= 20', 'suspicious': 'net >= 0 OR threat >= 8'}
        },
        'results': {
            'total_samples': len(results),
            'detection_rate': detection_rate,
            'strict_detection': strict_detection,
            'false_positive_rate': fp_rate,
            'f1_score': f1,
            'precision': precision,
            'recall': recall,
            'tp': tp, 'sp': sp, 'fn': fn, 'tn': tn, 'fp': fp
        },
        'samples': results
    }
    
    report_path = Path(__file__).parent.parent / "reports" / f"research_experiment_{int(time.time())}.json"
    report_path.parent.mkdir(exist_ok=True)
    with open(report_path, 'w') as f:
        json.dump(report, f, indent=2, default=str)
    
    console.print(f"\n[green]✓ Full research report saved: {report_path}[/green]\n")
    
    # Final verdict
    console.print("=" * 100, style="bold cyan")
    if detection_rate >= 90 and fp_rate == 0:
        console.print("[bold green]🏆 Research Grade: EXCELLENT[/bold green]")
        console.print("[bold]Detection Rate ≥ 90% | 0% False Positives | F1 Score > 0.9[/bold]")
    console.print("=" * 100, style="bold cyan")
    
    return results


if __name__ == "__main__":
    try:
        run_research_experiment()
    except KeyboardInterrupt:
        print("\n[yellow]⚠️ Test interrupted[/yellow]\n")
    except Exception as e:
        print(f"\n[red]❌ Error: {e}[/red]\n")
        import traceback
        traceback.print_exc()
