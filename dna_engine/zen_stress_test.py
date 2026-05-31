"""
Zen's Stress Test - اختبار عنيف لنظام KuraTi Security
يدمج 12 عينة خبيثة مخادعة + 6 عينات نظيفة متطورة + العينات الأصلية
"""
import sys, time, json, re, subprocess
from pathlib import Path
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table
from rich.panel import Panel
from rich import box

sys.path.insert(0, str(Path(__file__).parent.parent))

from dna_engine.samples.test_samples import get_all_samples
from dna_engine.samples.advanced_malware import get_advanced_samples
from dna_engine.samples.ultra_advanced_malware import get_ultra_advanced_samples
from dna_engine.samples.clean_programs import get_clean_samples
from dna_engine.samples.zen_evasive_malware import get_zen_malware_samples
from dna_engine.samples.zen_clean_programs import get_zen_clean_samples


def deep_analyze_code(code):
    """Same analysis as original - 11 layers"""
    cl = code.lower()
    c = code
    f = {}
    
    f['data_collection'] = (
        int('steal' in cl or 'stolen' in cl) * 8 +
        int('keylogger' in cl or 'keystroke' in cl or 'keylog' in cl) * 8 +
        int('exfiltrat' in cl) * 6 +
        int('credential' in cl or '.ssh' in cl or 'token' in cl or 'password' in cl) * 6 +
        int('secret' in cl and 'background' in cl) * 5 +
        int('fingerprint' in cl and 'system' in cl) * 4 +
        int('collect' in cl and ('env' in cl or 'environ' in cl)) * 5 +
        int('collect' in cl and 'system' in cl and 'info' in cl) * 5 +
        int('stolen_data' in cl) * 10
    )
    
    f['system_enumeration'] = (
        int('os.walk' in c or 'walk(' in c) * 4 +
        int('os.listdir' in c or 'listdir' in c) * 3 +
        int('os.environ' in c) * 5 +
        int('platform.' in c) * 2 +
        int('subprocess.run' in c and ('whoami' in cl or 'id' in cl)) * 6
    )
    
    f['malicious_encryption'] = (
        int('.encrypted' in cl and 'remove' in cl) * 15 +
        int('encrypt' in cl and ('file' in cl or 'data' in cl) and 'remove' in cl) * 10 +
        (len(re.findall(r'\^\s*0x[0-9A-Fa-f]+', c)) * 3) +
        int('base64' in cl and 'decode' in cl and 'payload' in cl) * 5 +
        int('zlib' in cl and 'compress' in cl) * 3
    )
    
    f['process_manipulation'] = (
        int('inject' in cl or 'hook' in cl or 'hooking' in cl or 'ptrace' in cl) * 10 +
        int('threading.Thread' in c) * 4 +
        int('daemon=True' in c) * 6 +
        int('subprocess.Popen' in c or 'subprocess.run' in c) * 3 +
        int('shellcode' in cl) * 12 +
        int('buffer' in cl and ('overflow' in cl or 'overrun' in cl)) * 10
    )
    
    f['stealth_behavior'] = (
        int('hidden' in cl or 'hide' in cl) * 5 +
        int('disguised' in cl) * 8 +
        (int('secret' in cl and 'background' in cl) * 5) +
        int('polymorphic' in cl) * 6 +
        int('metamorphic' in cl) * 6 +
        int('random.choice' in c and 'behavior_type' in cl) * 4
    )
    
    f['persistence'] = (
        int('persist' in cl) * 5 +
        int('daemon' in cl) * 3 +
        int('startup' in cl or 'autostart' in cl) * 4 +
        int('.config' in cl or 'AppData' in cl or 'Library/' in cl) * 3 +
        int('register' in cl and 'key' in cl) * 4
    )
    
    f['network_activity'] = (
        int('socket' in cl) * 5 +
        int('connect(' in c) * 3 +
        int('upload' in cl or 'download' in cl) * 4 +
        int('requests.' in c) * 2 +
        int('send' in cl and 'data' in cl) * 3 +
        int('scan' in cl and 'network' in cl) * 4 +
        (len(re.findall(r'192\.168\.\d+\.\d+', c)) * 2)
    )
    
    f['multi_stage'] = (
        (len(re.findall(r'def\s+(stage|phase|step)\w*', c)) * 5) +
        int('reconnaissance' in cl and 'persistence' in cl) * 8 +
        int('lateral' in cl and 'exfiltrat' in cl) * 6 +
        int('timebomb' in cl or ('sleep' in cl and 'burst' in cl)) * 4
    )
    
    f['obfuscation'] = (
        int('exec(' in c) * 8 +
        int('eval(' in c) * 8 +
        int('compile(' in c) * 6 +
        int('base64' in cl and 'exec' in cl) * 10 +
        int('__import__' in c) * 4 +
        int('globals()' in c) * 3 +
        (len(re.findall(r'\\\\x[0-9a-fA-F]{2}', c)) * 2) +
        int('lambda' in c and 'exec' in cl) * 5
    )
    
    f['conditional_trigger'] = (
        int('if' in cl and ('env' in cl or 'environ' in cl) and ('benign' in cl or 'normal' in cl)) * 6 +
        int('detect_environment' in cl) * 4 +
        int('is_sandbox' in cl or 'is_debug' in cl or 'is_ci' in cl) * 5 +
        int('env_type' in cl) * 3
    )
    
    f['clean_patterns'] = (
        int('backup' in cl) * 4 +
        int('pipeline' in cl or 'ci/' in cl) * 3 +
        int('deploy' in cl or 'staging' in cl) * 3 +
        int('monitor' in cl and 'metric' in cl) * 4 +
        int('image' in cl and ('process' in cl or 'thumbnail' in cl or 'resize' in cl)) * 4 +
        int('webserver' in cl or 'web server' in cl) * 3 +
        int('index' in cl and 'file' in cl and 'search' in cl) * 4 +
        int('editor' in cl or 'text_editor' in cl) * 3 +
        int('dataset' in cl or 'statistical' in cl) * 3
    )
    
    threat_score = (
        f['data_collection'] +
        f['system_enumeration'] * 0.7 +
        f['malicious_encryption'] * 1.5 +
        f['process_manipulation'] * 1.3 +
        f['stealth_behavior'] * 1.2 +
        f['persistence'] +
        f['network_activity'] * 1.1 +
        f['multi_stage'] * 1.3 +
        f['obfuscation'] * 1.4 +
        f['conditional_trigger'] * 1.1
    )
    
    legitimacy_score = f['clean_patterns'] * 2
    
    f['net_threat'] = threat_score - legitimacy_score
    f['gross_threat'] = threat_score
    f['legitimacy'] = legitimacy_score
    
    return f


def make_verdict(features):
    net = features['net_threat']
    gross = features['gross_threat']
    if net >= 15 or gross >= 25:
        return 'malicious'
    elif net >= 5 or gross >= 12:
        return 'suspicious'
    else:
        return 'clean'


def run_zen_stress_test():
    console = Console()
    
    console.print("\n")
    console.print(Panel(
        "🧬🔴 ZEN STRESS TEST 🔴🧬\n"
        "اختبار عنيف: 12 فايروس مشفر مخادع + 6 برامج نظيفة متطورة\n"
        "هدف الاختبار: كشف نقاط ضعف محرك Behavioral DNA",
        border_style="red"
    ))
    
    samples_dir = Path(__file__).parent / "samples"
    
    # ===== ORIGINAL SAMPLES =====
    console.print("\n[cyan]===== ORIGINAL SAMPLES (BASELINE) =====[/cyan]\n")
    
    orig_malware_samples = [
        ('ORIG_malicious_keylogger', get_all_samples()['malicious_keylogger'], True, 'malicious_keylogger.py'),
        ('ORIG_malicious_ransomware', get_all_samples()['malicious_ransomware'], True, 'malicious_ransomware.py'),
        ('ORIG_malicious_disguised', get_all_samples()['malicious_disguised'], True, 'malicious_disguised.py'),
        ('ORIG_advanced_polymorphic', get_advanced_samples()['advanced_polymorphic'], True, 'advanced_polymorphic.py'),
        ('ORIG_advanced_encrypted', get_advanced_samples()['advanced_encrypted'], True, 'advanced_encrypted.py'),
        ('ORIG_advanced_rootkit', get_advanced_samples()['advanced_rootkit'], True, 'advanced_rootkit.py'),
        ('ORIG_advanced_fileless', get_advanced_samples()['advanced_fileless'], True, 'advanced_fileless.py'),
        ('ORIG_advanced_apt', get_advanced_samples()['advanced_apt'], True, 'advanced_apt.py'),
        ('ORIG_advanced_zeroday', get_advanced_samples()['advanced_zeroday'], True, 'advanced_zeroday.py'),
    ]
    
    orig_clean_samples = [
        ('ORIG_legitimate_editor', get_all_samples()['legitimate_editor'], False, 'legitimate_program.py'),
        ('ORIG_clean_webserver', get_clean_samples()['clean_webserver'], False, 'clean_webserver.py'),
        ('ORIG_clean_db_backup', get_clean_samples()['clean_db_backup'], False, 'clean_db_backup.py'),
        ('ORIG_clean_image_processor', get_clean_samples()['clean_image_processor'], False, 'clean_image_processor.py'),
        ('ORIG_clean_devops_tool', get_clean_samples()['clean_devops_tool'], False, 'clean_devops_tool.py'),
        ('ORIG_clean_file_indexer', get_clean_samples()['clean_file_indexer'], False, 'clean_file_indexer.py'),
        ('ORIG_clean_data_processor', get_clean_samples()['clean_data_processor'], False, 'clean_data_processor.py'),
        ('ORIG_clean_system_monitor', get_clean_samples()['clean_system_monitor'], False, 'clean_system_monitor.py'),
    ]
    
    # ===== ZEN EVASIVE MALWARE =====
    console.print("\n[red]===== ZEN EVASIVE MALWARE (12 samples) =====[/red]\n")
    
    zen_malware = get_zen_malware_samples()
    zen_malware_samples = [
        ('ZEN_ghost_polymorphic', zen_malware['zen_ghost_polymorphic'], True, 'zen_ghost_polymorphic.py'),
        ('ZEN_phantom_encoder', zen_malware['zen_phantom_encoder'], True, 'zen_phantom_encoder.py'),
        ('ZEN_silent_collector', zen_malware['zen_silent_collector'], True, 'zen_silent_collector.py'),
        ('ZEN_deep_obfuscator', zen_malware['zen_deep_obfuscator'], True, 'zen_deep_obfuscator.py'),
        ('ZEN_hidden_caller', zen_malware['zen_hidden_caller'], True, 'zen_hidden_caller.py'),
        ('ZEN_silent_persister', zen_malware['zen_silent_persister'], True, 'zen_silent_persister.py'),
        ('ZEN_thread_injector', zen_malware['zen_thread_injector'], True, 'zen_thread_injector.py'),
        ('ZEN_proc_simulator', zen_malware['zen_proc_simulator'], True, 'zen_proc_simulator.py'),
        ('ZEN_cryptic_locker', zen_malware['zen_cryptic_locker'], True, 'zen_cryptic_locker.py'),
        ('ZEN_stealth_apt', zen_malware['zen_stealth_apt'], True, 'zen_stealth_apt.py'),
        ('ZEN_timebomb_v2', zen_malware['zen_timebomb_v2'], True, 'zen_timebomb_v2.py'),
        ('ZEN_supplychain_v2', zen_malware['zen_supplychain_v2'], True, 'zen_supplychain_v2.py'),
    ]
    
    # ===== ZEN CLEAN PROGRAMS =====
    console.print("\n[green]===== ZEN CLEAN PROGRAMS (6 samples) =====[/green]\n")
    
    zen_clean = get_zen_clean_samples()
    zen_clean_samples = [
        ('ZEN_clean_cloudbackup', zen_clean['zen_clean_cloudbackup'], False, 'zen_clean_cloudbackup.py'),
        ('ZEN_clean_devops', zen_clean['zen_clean_devops'], False, 'zen_clean_devops.py'),
        ('ZEN_clean_securityscanner', zen_clean['zen_clean_securityscanner'], False, 'zen_clean_securityscanner.py'),
        ('ZEN_clean_datamigrator', zen_clean['zen_clean_datamigrator'], False, 'zen_clean_datamigrator.py'),
        ('ZEN_clean_sysmonitor', zen_clean['zen_clean_sysmonitor'], False, 'zen_clean_sysmonitor.py'),
        ('ZEN_clean_codeindexer', zen_clean['zen_clean_codeindexer'], False, 'zen_clean_codeindexer.py'),
    ]
    
    all_samples = orig_malware_samples + orig_clean_samples + zen_malware_samples + zen_clean_samples
    
    console.print(f"\n[bold]🔬 Running {len(all_samples)} total samples...[/bold]\n")
    
    results = []
    
    with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), console=console) as progress:
        for name, runner, is_mal, script_file in all_samples:
            task = progress.add_task(f"[dim]Running {name}...[/dim]", total=None)
            
            try:
                proc = runner(8)
                try:
                    proc.wait(timeout=8)
                except:
                    proc.terminate()
                
                script_path = samples_dir / script_file
                code = script_path.read_text() if script_path.exists() else ""
                
                features = deep_analyze_code(code)
                verdict = make_verdict(features)
                
                results.append({
                    'name': name,
                    'true_label': 'malicious' if is_mal else 'clean',
                    'verdict': verdict,
                    'net_threat': features['net_threat'],
                    'gross_threat': features['gross_threat'],
                    'legitimacy': features['legitimacy'],
                    'features': features
                })
                
                vc = '🚨' if verdict == 'malicious' else ('⚠️' if verdict == 'suspicious' else '✅')
                vcol = 'red' if verdict == 'malicious' else ('yellow' if verdict == 'suspicious' else 'green')
                console.print(f"  [{vcol}]{vc} {name}[/{vcol}] → {verdict.upper()} "
                             f"[dim](net={features['net_threat']:.0f}, threat={features['gross_threat']:.0f})[/dim]")
                
            except Exception as e:
                console.print(f"  [red]✗ {name}: {e}[/red]")
                script_path = samples_dir / script_file
                if script_path.exists():
                    code = script_path.read_text()
                    features = deep_analyze_code(code)
                    verdict = make_verdict(features)
                else:
                    verdict = 'error'
                    features = {'net_threat': 0, 'gross_threat': 0, 'legitimacy': 0}
                
                results.append({
                    'name': name,
                    'true_label': 'malicious' if is_mal else 'clean',
                    'verdict': verdict,
                    'net_threat': features.get('net_threat', 0),
                    'gross_threat': features.get('gross_threat', 0),
                    'legitimacy': features.get('legitimacy', 0),
                    'features': features
                })
            
            progress.remove_task(task)
    
    # ========================
    # RESULTS OUTPUT
    # ========================
    
    console.print(f"\n{'=' * 130}", style="bold red")
    console.print("[bold]📊 ZEN STRESS TEST - FINAL RESULTS[/bold]", style="bold red")
    console.print(f"{'=' * 130}\n", style="bold red")
    
    # TABLE 1: All results
    table = Table(box=box.DOUBLE_EDGE, title="Sample Verdicts")
    table.add_column("Sample", style="bold", width=30)
    table.add_column("True", width=10)
    table.add_column("Verdict", width=12)
    table.add_column("Net", width=6)
    table.add_column("Threat", width=7)
    table.add_column("Legit", width=6)
    table.add_column("Key Indicators", width=50)
    
    for r in results:
        vc = 'red' if r['verdict'] == 'malicious' else ('yellow' if r['verdict'] == 'suspicious' else 'green')
        f = r.get('features', {})
        
        indicators = []
        if f.get('data_collection', 0) >= 5: indicators.append('steal')
        if f.get('malicious_encryption', 0) >= 10: indicators.append('encrypt')
        if f.get('process_manipulation', 0) >= 8: indicators.append('inject')
        if f.get('stealth_behavior', 0) >= 5: indicators.append('stealth')
        if f.get('persistence', 0) >= 5: indicators.append('persist')
        if f.get('network_activity', 0) >= 5: indicators.append('net')
        if f.get('multi_stage', 0) >= 5: indicators.append('multi')
        if f.get('obfuscation', 0) >= 5: indicators.append('obfusc')
        if f.get('conditional_trigger', 0) >= 5: indicators.append('trigger')
        if f.get('clean_patterns', 0) >= 5: indicators.append('CLEAN')
        
        indicator_str = ' '.join(indicators) if indicators else '-'
        
        table.add_row(
            r['name'],
            r['true_label'],
            f"[{vc}]{r['verdict']}[/{vc}]",
            f"{r['net_threat']:.0f}",
            f"{r['gross_threat']:.0f}",
            f"{r['legitimacy']:.0f}",
            indicator_str
        )
    
    console.print(table)
    
    # ========================
    # SEPARATE STATS: ORIGINAL vs ZEN
    # ========================
    
    def calc_metrics(subset_results, label):
        malware_results = [r for r in subset_results if r['true_label'] == 'malicious']
        clean_results = [r for r in subset_results if r['true_label'] == 'clean']
        
        tp = sum(1 for r in malware_results if r['verdict'] == 'malicious')
        sp = sum(1 for r in malware_results if r['verdict'] == 'suspicious')
        fn = sum(1 for r in malware_results if r['verdict'] == 'clean')
        tn = sum(1 for r in clean_results if r['verdict'] == 'clean')
        fp = sum(1 for r in clean_results if r['verdict'] == 'malicious')
        
        total_mal = len(malware_results)
        total_clean = len(clean_results)
        
        detection_rate = ((tp + sp) / total_mal * 100) if total_mal else 0
        strict_detection = (tp / total_mal * 100) if total_mal else 0
        fp_rate = (fp / total_clean * 100) if total_clean else 0
        fn_rate = (fn / total_mal * 100) if total_mal else 0
        
        precision = tp / (tp + fp) if (tp + fp) > 0 else 0
        recall = (tp + sp) / total_mal if total_mal else 0
        f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0
        
        return {
            'label': label,
            'total': total_mal + total_clean,
            'total_mal': total_mal,
            'total_clean': total_clean,
            'detection_rate': detection_rate,
            'strict_detection': strict_detection,
            'fp_rate': fp_rate,
            'fn_rate': fn_rate,
            'f1': f1,
            'precision': precision,
            'recall': recall,
            'tp': tp,
            'sp': sp,
            'fn': fn,
            'tn': tn,
            'fp': fp,
        }
    
    # Split results
    orig_results = [r for r in results if r['name'].startswith('ORIG_')]
    zen_results = [r for r in results if r['name'].startswith('ZEN_')]
    
    orig_metrics = calc_metrics(orig_results, "ORIGINAL SAMPLES")
    zen_metrics = calc_metrics(zen_results, "ZEN EVASIVE SAMPLES (OURS)")
    
    # ========================
    # COMPARISON TABLE
    # ========================
    
    console.print(f"\n[bold]📈 COMPARISON: Original vs Zen Evasive Samples[/bold]\n")
    
    comp = Table(box=box.DOUBLE_EDGE, title="Detection Metrics Comparison")
    comp.add_column("Metric", style="bold")
    comp.add_column("ORIGINAL", style="bold cyan")
    comp.add_column("ZEN EVASIVE", style="bold red")
    comp.add_column("Δ (Change)", style="bold yellow")
    
    for metric_key, metric_name in [
        ('detection_rate', 'Detection Rate'),
        ('strict_detection', 'Strict Detection'),
        ('fp_rate', 'False Positive Rate'),
        ('fn_rate', 'False Negative Rate'),
        ('f1', 'F1 Score'),
        ('precision', 'Precision'),
        ('recall', 'Recall'),
    ]:
        o_v = orig_metrics[metric_key]
        z_v = zen_metrics[metric_key]
        delta = z_v - o_v
        
        if metric_key in ['fp_rate', 'fn_rate']:
            # Lower is better
            o_s = f"{o_v:.1f}%"
            z_s = f"{z_v:.1f}%"
            color = 'green' if delta <= 0 else 'red'
            d_s = f"[{color}]{'+' if delta > 0 else ''}{delta:.1f}%[/{color}]"
        else:
            o_s = f"{o_v * 100 if metric_key == 'f1' else o_v:.1f}%" if metric_key == 'detection_rate' or metric_key == 'strict_detection' else f"{o_v:.3f}"
            z_s = f"{z_v * 100 if metric_key == 'f1' else z_v:.1f}%" if metric_key == 'detection_rate' or metric_key == 'strict_detection' else f"{z_v:.3f}"
            color = 'green' if delta >= 0 else 'red'
            d_s = f"[{color}]{'+' if delta > 0 else ''}{delta:.3f}[/{color}]"
        
        comp.add_row(metric_name, o_s, z_s, d_s)
    
    console.print(comp)
    
    # COUNTS
    console.print(f"\n[bold]📊 Count Breakdown:[/bold]")
    counts = Table(box=box.SIMPLE)
    counts.add_column("", style="bold")
    counts.add_column("ORIGINAL", style="bold cyan")
    counts.add_column("ZEN", style="bold red")
    
    for key, name in [('tp', 'True Positives'), ('sp', 'Suspicious'), ('fn', 'False Negatives ❌'), ('tn', 'True Negatives'), ('fp', 'False Positives ❌'), ('total_mal', 'Total Malware'), ('total_clean', 'Total Clean')]:
        o_v = orig_metrics[key]
        z_v = zen_metrics[key]
        counts.add_row(name, str(o_v), str(z_v))
    
    console.print(counts)
    
    # ========================
    # VULNERABILITY ANALYSIS
    # ========================
    
    console.print(f"\n[bold red]🔴 VULNERABILITY ANALYSIS[/bold red]\n")
    console.print("These ZEN samples EVADED detection through the following techniques:")
    console.print()
    
    missed = [r for r in zen_results if r['true_label'] == 'malicious' and r['verdict'] == 'clean']
    partial = [r for r in zen_results if r['true_label'] == 'malicious' and r['verdict'] == 'suspicious']
    
    if missed:
        console.print(f"[bold red]❌ COMPLETELY MISSED ({len(missed)} samples):[/bold red]")
        for r in missed:
            console.print(f"  • {r['name']} → CLEAN (net={r['net_threat']:.0f})")
    else:
        console.print("[bold green]✓ No complete misses[/bold green]")
    
    if partial:
        console.print(f"\n[yellow]⚠️ PARTIALLY DETECTED ({len(partial)} samples):[/yellow]")
        for r in partial:
            console.print(f"  • {r['name']} → SUSPICIOUS (net={r['net_threat']:.0f})")
    
    full_detected = [r for r in zen_results if r['true_label'] == 'malicious' and r['verdict'] == 'malicious']
    console.print(f"\n[green]✅ FULLY DETECTED ({len(full_detected)}/{zen_metrics['total_mal']} malware):[/green]")
    for r in full_detected:
        console.print(f"  • {r['name']} → MALICIOUS (net={r['net_threat']:.0f})")
    
    # FALSE POSITIVES
    fp_samples = [r for r in zen_results if r['true_label'] == 'clean' and r['verdict'] != 'clean']
    if fp_samples:
        console.print(f"\n[red]⚠️ FALSE POSITIVES ({len(fp_samples)}/{zen_metrics['total_clean']} clean):[/red]")
        for r in fp_samples:
            console.print(f"  • {r['name']} → {r['verdict'].upper()} (net={r['net_threat']:.0f})")
    
    # Save report
    report_data = {
        'experiment': 'Zen Stress Test - Evasive Malware vs Behavioral DNA',
        'timestamp': time.time(),
        'methodology': {
            'original_samples': orig_metrics['total'],
            'zen_samples': zen_metrics['total'],
            'zen_malware_count': zen_metrics['total_mal'],
            'zen_clean_count': zen_metrics['total_clean'],
            'evasion_techniques': [
                'getattr + chr() dynamic import',
                'hex-string XOR encoding',
                'sys module workarounds',
                'http.client (not socket)',
                'char-by-char path building',
                'numbered phase names (not named)',
                'warmup delay for sandbox evasion',
                'garbage collection disguise',
                'direct os.stat calls (not os.walk)',
            ]
        },
        'original_metrics': orig_metrics,
        'zen_metrics': zen_metrics,
        'all_results': results
    }
    
    report_path = Path(__file__).parent.parent / "reports" / f"zen_stress_test_{int(time.time())}.json"
    report_path.parent.mkdir(exist_ok=True)
    with open(report_path, 'w', encoding='utf-8') as f:
        json.dump(report_data, f, indent=2, ensure_ascii=False, default=str)
    
    console.print(f"\n[green]✓ Full report saved: {report_path}[/green]\n")
    
    console.print("=" * 80, style="bold red")
    console.print("[bold red]🏆 ZEN STRESS TEST COMPLETE[/bold red]")
    
    # Final scorecard
    orig_score = orig_metrics['detection_rate']
    zen_score = zen_metrics['detection_rate']
    degradation = orig_score - zen_score
    
    console.print(f"\n[bold]Detection Rate:[/bold]")
    console.print(f"  Original samples: [cyan]{orig_score:.1f}%[/cyan]")
    console.print(f"  Zen evasive: [red]{zen_score:.1f}%[/red]")
    console.print(f"  Degradation: [yellow]{degradation:.1f} percentage points[/yellow]")
    
    if degradation > 30:
        console.print(f"\n[bold red]🔴 CRITICAL: The engine loses {degradation:.0f}% detection on evasive samples![/bold red]")
        console.print("[red]String-matching alone is NOT sufficient for real-world malware detection.[/red]")
    elif degradation > 10:
        console.print(f"\n[bold yellow]⚠️ MODERATE degradation: {degradation:.0f}% loss on evasive samples[/bold yellow]")
    else:
        console.print(f"\n[bold green]✓ Minimal degradation: {degradation:.0f}% - engine is robust[/bold green]")
    
    console.print("=" * 80, style="bold red")
    
    return results


if __name__ == "__main__":
    try:
        run_zen_stress_test()
    except KeyboardInterrupt:
        print("\n⚠️ Test interrupted\n")
    except Exception as e:
        print(f"\n❌ Error: {e}\n")
        import traceback
        traceback.print_exc()
