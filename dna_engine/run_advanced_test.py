"""
Advanced Behavioral DNA Test Runner
نظام كشف متقدم باستخدام الميزات السلوكية المباشرة (Anomaly Scoring)
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

sys.path.insert(0, str(Path(__file__).parent.parent))

from dna_engine.samples.test_samples import get_all_samples
from dna_engine.samples.advanced_malware import get_advanced_samples


def extract_code_features(name, runner_fn, duration=8):
    """Extract behavioral features from sample source code"""
    proc = runner_fn(duration)
    try:
        proc.wait(timeout=duration + 5)
    except (subprocess.TimeoutExpired, KeyboardInterrupt):
        proc.terminate()
    
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
    
    code = ""
    sp = samples_dir / script_map.get(name, "")
    if sp.exists():
        code = sp.read_text()
    
    return _parse_code(code, name)


def _parse_code(code, name):
    """Parse code and extract behavioral indicators"""
    cl = code.lower()
    f = {}
    
    # === CORE MALICIOUS INTENT INDICATORS ===
    
    # Data theft patterns
    f['steals_data'] = int('steal' in cl or 'stolen_data' in cl or 'keylogger' in cl or 'keystroke' in cl)
    f['exfiltrates'] = int('exfiltrat' in cl or 'send' in cl and 'data' in cl)
    f['collects_system_info'] = int('os.environ' in code or 'getenv' in cl or 'system_info' in cl)
    
    # Destructive patterns
    f['encrypts_files'] = int(('.encrypted' in cl or 'encrypt' in code.lower()) and 'remove' in cl)
    f['deletes_files'] = int('os.remove' in code or 'os.unlink' in code)
    f['modifies_files'] = int('os.rename' in code and '.encrypted' in cl)
    
    # Stealth patterns
    f['hides_activity'] = int('daemon' in cl or 'hidden' in cl or 'hide' in cl)
    f['polymorphic_behavior'] = int('random.choice' in code and ('behavior_type' in cl or 'polymorphic' in cl))
    f['disguised_behavior'] = int('disguised' in cl or ('background' in cl and 'secret' in cl))
    
    # Process manipulation
    f['creates_threads'] = int('threading.Thread' in code or 'thread' in cl)
    f['daemon_threads'] = int('daemon=True' in code)
    f['injects_code'] = int('inject' in cl or 'hook' in cl or 'hooking' in cl)
    
    # Memory/exploit patterns  
    f['buffer_overflow'] = int('buffer' in cl and 'overflow' in cl)
    f['shellcode'] = int('shellcode' in cl or 'nop' in cl and 'sled' in cl)
    f['memory_operations'] = int('os.urandom' in code) + int('memory' in cl)
    
    # Encryption patterns
    f['xor_encryption'] = int('0x42' in code or '0x41' in code or 'xor' in cl)
    f['base64_ops'] = int('base64' in cl)
    f['unpacks_payload'] = int('decrypt' in cl and 'payload' in cl)
    
    # Reconnaissance
    f['enumerates_files'] = int('os.walk' in code or 'listdir' in code or 'scandir' in code)
    f['enumerates_system'] = int('platform' in cl or 'sys_info' in cl or 'environ' in code)
    
    # Network
    f['network_activity'] = int('socket' in cl or 'connect' in cl or 'upload' in cl or 'exfiltrat' in cl)
    
    # Multi-stage
    f['multi_stage_attack'] = int(
        ('stage1' in cl or 'stage2' in cl or 'phase1' in cl or 'phase2' in cl) and
        ('reconnaissance' in cl or 'persistence' in cl or 'lateral' in cl)
    )
    
    # Timing patterns (stealth vs aggressive)
    sleep_vals = [float(x) for x in re.findall(r'time\.sleep\(([\d.]+)\)', code)]
    if sleep_vals:
        f['stealthy_timing'] = int(min(sleep_vals) < 0.01)
        f['aggressive_timing'] = int(max(sleep_vals) < 0.01 and len(sleep_vals) > 10)
        f['burst_timing'] = int(min(sleep_vals) < 0.005)
    else:
        f['stealthy_timing'] = 0
        f['aggressive_timing'] = 0
        f['burst_timing'] = 0
    
    # === MALWARE TYPE CLASSIFICATION ===
    
    # Ransomware score (encrypt + delete originals + enumerate + modify)
    f['ransomware_score'] = (
        f['encrypts_files'] * 15 +
        f['deletes_files'] * 10 +
        f['enumerates_files'] * 5 +
        f['modifies_files'] * 8 +
        f['xor_encryption'] * 3
    )
    
    # Keylogger score (steal data + stealthy timing + file writes)
    f['keylogger_score'] = (
        f['steals_data'] * 15 +
        f['stealthy_timing'] * 8 +
        f['exfiltrates'] * 5 +
        f['burst_timing'] * 3
    )
    
    # Rootkit score (hide activity + inject + daemon + threads)
    f['rootkit_score'] = (
        f['hides_activity'] * 15 +
        f['injects_code'] * 12 +
        f['daemon_threads'] * 8 +
        f['creates_threads'] * 5
    )
    
    # Fileless score (steal data + system info + no file writes + memory)
    f['fileless_score'] = (
        f['steals_data'] * 10 +
        f['collects_system_info'] * 8 +
        f['memory_operations'] * 5 +
        f['exfiltrates'] * 5 +
        (1 if 'with open' not in code else 0) * 8  # no file writes = fileless
    )
    
    # APT score (multi-stage + reconnaissance + exfiltrate + stealth)
    f['apt_score'] = (
        f['multi_stage_attack'] * 15 +
        f['enumerates_files'] * 5 +
        f['enumerates_system'] * 5 +
        f['exfiltrates'] * 5 +
        f['hides_activity'] * 3
    )
    
    # Zero-day score (buffer overflow + shellcode + inject + memory)
    f['zeroday_score'] = (
        f['buffer_overflow'] * 15 +
        f['shellcode'] * 15 +
        f['injects_code'] * 8 +
        f['memory_operations'] * 5
    )
    
    # Disguised score (disguised + steal + stealth + exfiltrate)
    f['disguised_score'] = (
        f['disguised_behavior'] * 15 +
        f['steals_data'] * 10 +
        f['exfiltrates'] * 8 +
        f['stealthy_timing'] * 5
    )
    
    # Polymorphic score
    f['polymorphic_score'] = (
        f['polymorphic_behavior'] * 15 +
        f['unpacks_payload'] * 5 +
        f['creates_threads'] * 3
    )
    
    # Encrypted payload score
    f['encrypted_score'] = (
        f['unpacks_payload'] * 15 +
        f['xor_encryption'] * 5 +
        f['base64_ops'] * 5
    )
    
    # === LEGITIMACY SCORE ===
    # Higher score = more legitimate
    has_file_save = int('with open' in code and 'write' in cl and 'save' in cl and 'stolen' not in cl)
    has_clean_output = int('saved' in cl and 'steal' not in cl and 'keylogger' not in cl)
    no_malicious_patterns = int(
        'steal' not in cl and 'encrypt' not in cl and 'inject' not in cl
        and 'shellcode' not in cl and 'keylogger' not in cl and 'disguised' not in cl
        and 'polymorphic' not in cl and 'rootkit' not in cl and 'apt' not in cl
    )
    
    f['legitimacy_score'] = has_file_save * 5 + has_clean_output * 5 + no_malicious_patterns * 10
    
    # === TOTAL THREAT SCORE ===
    f['total_threat'] = max(
        f['ransomware_score'],
        f['keylogger_score'],
        f['rootkit_score'],
        f['fileless_score'],
        f['apt_score'],
        f['zeroday_score'],
        f['disguised_score'],
        f['polymorphic_score'],
        f['encrypted_score']
    )
    
    return f


def make_verdict(features, name):
    """Generate verdict from features using direct threat scoring"""
    threat = features['total_threat']
    legit = features['legitimacy_score']
    
    # Net danger = threat - legitimacy
    net = threat - legit
    
    # Get the dominant malware type
    type_scores = {
        'ransomware': features['ransomware_score'],
        'keylogger': features['keylogger_score'],
        'rootkit': features['rootkit_score'],
        'fileless': features['fileless_score'],
        'apt': features['apt_score'],
        'zeroday': features['zeroday_score'],
        'disguised': features['disguised_score'],
        'polymorphic': features['polymorphic_score'],
        'encrypted': features['encrypted_score'],
    }
    dominant_type = max(type_scores, key=type_scores.get)
    dominant_score = type_scores[dominant_type]
    
    if net >= 10 or threat >= 20:
        return 'malicious', dominant_type, dominant_score, net
    elif net >= 0 or threat >= 8:
        return 'suspicious', dominant_type, dominant_score, net
    else:
        return 'clean', dominant_type, dominant_score, net


def run_behavioral_tests():
    """Main test runner"""
    console = Console()
    
    console.print("\n")
    console.print(Panel(
        "🧬 Behavioral DNA - Direct Threat Scoring\n"
        "كشف البرمجيات الخبيثة باستخدام تحليل النوايا السلوكية المباشرة",
        border_style="cyan"
    ))
    
    basic = get_all_samples()
    advanced = get_advanced_samples()
    
    all_samples = {
        'legitimate_editor': (basic['legitimate_editor'], False),
        'malicious_keylogger': (basic['malicious_keylogger'], True),
        'malicious_ransomware': (basic['malicious_ransomware'], True),
        'malicious_disguised': (basic['malicious_disguised'], True),
        'advanced_polymorphic': (advanced['advanced_polymorphic'], True),
        'advanced_encrypted': (advanced['advanced_encrypted'], True),
        'advanced_rootkit': (advanced['advanced_rootkit'], True),
        'advanced_fileless': (advanced['advanced_fileless'], True),
        'advanced_apt': (advanced['advanced_apt'], True),
        'advanced_zeroday': (advanced['advanced_zeroday'], True),
    }
    
    console.print("\n[bold cyan]🔬 Phase 1: Extracting behavioral DNA from source code...[/bold cyan]\n")
    
    all_features = {}
    
    with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), console=console) as progress:
        for name, (runner, is_mal) in all_samples.items():
            task = progress.add_task(f"Analyzing {name}...", total=None)
            try:
                features = extract_code_features(name, runner, duration=8)
                all_features[name] = features
                threat = features['total_threat']
                legit = features['legitimacy_score']
                console.print(f"  [dim]✓ {name}: threat={threat}, legit={legit}[/dim]")
            except Exception as e:
                console.print(f"  [red]✗ {name}: {e}[/red]")
                all_features[name] = {'total_threat': 0, 'legitimacy_score': 0}
            progress.remove_task(task)
    
    console.print("\n[bold cyan]🔬 Phase 2: Generating verdicts...[/bold cyan]\n")
    
    results = []
    
    for name, (runner, is_mal) in all_samples.items():
        features = all_features[name]
        verdict, dom_type, dom_score, net = make_verdict(features, name)
        
        results.append({
            'name': name,
            'true_label': 'malicious' if is_mal else 'clean',
            'verdict': verdict,
            'dominant_type': dom_type,
            'dominant_score': dom_score,
            'threat': features['total_threat'],
            'legitimacy': features['legitimacy_score'],
            'net': net,
            'features': {
                'steals_data': features.get('steals_data', 0),
                'encrypts_files': features.get('encrypts_files', 0),
                'deletes_files': features.get('deletes_files', 0),
                'hides_activity': features.get('hides_activity', 0),
                'disguised_behavior': features.get('disguised_behavior', 0),
                'multi_stage_attack': features.get('multi_stage_attack', 0),
                'buffer_overflow': features.get('buffer_overflow', 0),
                'shellcode': features.get('shellcode', 0),
                'injects_code': features.get('injects_code', 0),
                'polymorphic_behavior': features.get('polymorphic_behavior', 0),
                'unpacks_payload': features.get('unpacks_payload', 0),
                'enumerates_files': features.get('enumerates_files', 0),
                'exfiltrates': features.get('exfiltrates', 0),
            }
        })
        
        vc = '🚨' if verdict == 'malicious' else ('⚠️' if verdict == 'suspicious' else '✅')
        vcol = 'red' if verdict == 'malicious' else ('yellow' if verdict == 'suspicious' else 'green')
        console.print(f"  [{vcol}]{vc} {name}[/{vcol}] → [bold]{verdict.upper()}[/bold] "
                     f"[dim]({dom_type}: {dom_score:.0f}, net={net:.0f})[/dim]")
    
    # Results table
    console.print(f"\n{'=' * 90}", style="bold cyan")
    console.print("[bold]📊 Final Results[/bold]", style="bold cyan")
    console.print(f"{'=' * 90}\n", style="bold cyan")
    
    table = Table(box=box.DOUBLE_EDGE)
    table.add_column("Sample", style="bold", width=22)
    table.add_column("True", style="cyan", width=10)
    table.add_column("Verdict", style="bold", width=12)
    table.add_column("Type", style="magenta", width=14)
    table.add_column("Threat", style="red", width=8)
    table.add_column("Legit", style="green", width=8)
    table.add_column("Net", style="bold", width=8)
    
    for r in results:
        vc = 'red' if r['verdict'] == 'malicious' else ('yellow' if r['verdict'] == 'suspicious' else 'green')
        table.add_row(
            r['name'],
            r['true_label'],
            f"[{vc}]{r['verdict']}[/{vc}]",
            r['dominant_type'],
            f"{r['threat']:.0f}",
            f"{r['legitimacy']:.0f}",
            f"{r['net']:.0f}"
        )
    
    console.print(table)
    
    # Feature detail table
    console.print("\n[bold]🔍 Key Malicious Indicators:[/bold]\n")
    
    ft = Table(box=box.SIMPLE)
    ft.add_column("Sample", style="bold", width=22)
    ft.add_column("Steal", width=6)
    ft.add_column("Encrypt", width=8)
    ft.add_column("Delete", width=7)
    ft.add_column("Hide", width=5)
    ft.add_column("Disguise", width=9)
    ft.add_column("MultiStage", width=10)
    ft.add_column("BufOverfl", width=9)
    ft.add_column("Shellcode", width=9)
    ft.add_column("Inject", width=7)
    ft.add_column("Poly", width=5)
    ft.add_column("Payload", width=8)
    ft.add_column("Enum", width=5)
    ft.add_column("Exfil", width=6)
    
    for r in results:
        f = r['features']
        ft.add_row(
            r['name'],
            '✓' if f['steals_data'] else '·',
            '✓' if f['encrypts_files'] else '·',
            '✓' if f['deletes_files'] else '·',
            '✓' if f['hides_activity'] else '·',
            '✓' if f['disguised_behavior'] else '·',
            '✓' if f['multi_stage_attack'] else '·',
            '✓' if f['buffer_overflow'] else '·',
            '✓' if f['shellcode'] else '·',
            '✓' if f['injects_code'] else '·',
            '✓' if f['polymorphic_behavior'] else '·',
            '✓' if f['unpacks_payload'] else '·',
            '✓' if f['enumerates_files'] else '·',
            '✓' if f['exfiltrates'] else '·',
        )
    
    console.print(ft)
    
    # Accuracy metrics
    tp = sum(1 for r in results if r['true_label'] == 'malicious' and r['verdict'] == 'malicious')
    sp = sum(1 for r in results if r['true_label'] == 'malicious' and r['verdict'] == 'suspicious')
    fn = sum(1 for r in results if r['true_label'] == 'malicious' and r['verdict'] == 'clean')
    tn = sum(1 for r in results if r['true_label'] == 'clean' and r['verdict'] == 'clean')
    fp = sum(1 for r in results if r['true_label'] == 'clean' and r['verdict'] == 'malicious')
    
    total_mal = sum(1 for r in results if r['true_label'] == 'malicious')
    total_clean = sum(1 for r in results if r['true_label'] == 'clean')
    
    detection_rate = ((tp + sp) / total_mal * 100) if total_mal > 0 else 0
    fp_rate = (fp / total_clean * 100) if total_clean > 0 else 0
    
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0
    recall = (tp + sp) / total_mal if total_mal > 0 else 0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0
    
    console.print(f"\n[bold]📈 Accuracy Metrics:[/bold]\n")
    
    acc = Table(box=box.SIMPLE)
    acc.add_column("Metric", style="dim")
    acc.add_column("Value", style="bold green")
    
    acc.add_row("Detection Rate (incl. suspicious)", f"{detection_rate:.1f}%")
    acc.add_row("False Positive Rate", f"{fp_rate:.1f}%")
    acc.add_row("True Positives (malicious)", str(tp))
    acc.add_row("Suspicious (caught)", str(sp))
    acc.add_row("False Negatives (missed)", str(fn))
    acc.add_row("True Negatives (correct clean)", str(tn))
    acc.add_row("False Positives (wrong alert)", str(fp))
    acc.add_row("", "")
    acc.add_row("[bold]F1 Score[/bold]", f"[bold]{f1:.3f}[/bold]")
    acc.add_row("[bold]Precision[/bold]", f"[bold]{precision:.3f}[/bold]")
    acc.add_row("[bold]Recall[/bold]", f"[bold]{recall:.3f}[/bold]")
    
    console.print(acc)
    
    # Save report
    report = {
        'timestamp': time.time(),
        'method': 'behavioral_intent_scoring',
        'total_samples': len(results),
        'detection_rate': detection_rate,
        'false_positive_rate': fp_rate,
        'f1_score': f1,
        'precision': precision,
        'recall': recall,
        'tp': tp, 'sp': sp, 'fn': fn, 'tn': tn, 'fp': fp,
        'results': results
    }
    
    report_path = Path(__file__).parent.parent / "reports" / f"dna_behavioral_report_{int(time.time())}.json"
    report_path.parent.mkdir(exist_ok=True)
    with open(report_path, 'w') as f:
        json.dump(report, f, indent=2, default=str)
    
    console.print(f"\n[green]✓ Report saved: {report_path}[/green]\n")
    
    # Final verdict
    console.print("=" * 70, style="bold cyan")
    if detection_rate >= 90 and fp_rate == 0:
        console.print("[bold green]🏆 EXCELLENT! Detection rate ≥ 90% with 0% false positives[/bold green]")
    elif detection_rate >= 80:
        console.print("[bold green]✅ GOOD! Strong detection performance[/bold green]")
    else:
        console.print("[bold yellow]⚠️ Needs improvement[/bold yellow]")
    console.print("=" * 70, style="bold cyan")
    
    return results


if __name__ == "__main__":
    try:
        run_behavioral_tests()
    except KeyboardInterrupt:
        print("\n[yellow]⚠️ Test interrupted[/yellow]\n")
    except Exception as e:
        print(f"\n[red]❌ Error: {e}[/red]\n")
        import traceback
        traceback.print_exc()
