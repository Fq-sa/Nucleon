"""
Zen Stress Test v2.0 - Combined Static + Runtime Analysis
اختبار شامل: تحليل ثابت + تحليل سلوكي Runtime
15 فايروس متعدد التشفير + 7 برامج نظيفة متطورة + العينات الأصلية
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
from dna_engine.samples.zenv2_ultra_malware import get_zenv2_malware_samples
from dna_engine.runtime_engine import (
    enhanced_static_analysis, 
    RuntimeMonitor, 
    combined_verdict,
    run_and_monitor,
)
import psutil


console = Console()


def run_zen_stress_test_v2():
    console.print("\n")
    console.print(Panel(
        "🧬🔴 ZEN STRESS TEST v2.0 🔴🧬\n"
        "Static Analysis + Runtime Behavioral Monitoring\n"
        "15 Ultra-Malware (AES-256, ChaCha20, Fernet, marshal, DH, XOR multi-key)\n"
        "7 Clean Programs + Original Baselines",
        border_style="red"
    ))
    
    samples_dir = Path(__file__).parent / "samples"
    
    # ===== BUILD SAMPLE LISTS =====
    
    # ZEN V2 MALWARE (15 samples - new crypto-advanced)
    z2_malware_raw = get_zenv2_malware_samples()
    z2_malware_samples = [
        ('Z2_aes256_ransomware', z2_malware_raw['zenv2_aes256_ransomware'], True, 'zenv2_aes256_ransomware.py'),
        ('Z2_chacha20_exfil', z2_malware_raw['zenv2_chacha20_exfil'], True, 'zenv2_chacha20_exfil.py'),
        ('Z2_marshal_injector', z2_malware_raw['zenv2_marshal_injector'], True, 'zenv2_marshal_injector.py'),
        ('Z2_fernet_backdoor', z2_malware_raw['zenv2_fernet_backdoor'], True, 'zenv2_fernet_backdoor.py'),
        ('Z2_rot13_hex_stealer', z2_malware_raw['zenv2_rot13_hex_stealer'], True, 'zenv2_rot13_hex_stealer.py'),
        ('Z2_xor_multikey', z2_malware_raw['zenv2_xor_multikey'], True, 'zenv2_xor_multikey.py'),
        ('Z2_antivm_trojan', z2_malware_raw['zenv2_antivm_trojan'], True, 'zenv2_antivm_trojan.py'),
        ('Z2_memmap_keylogger', z2_malware_raw['zenv2_memmap_keylogger'], True, 'zenv2_memmap_keylogger.py'),
        ('Z2_process_hollower', z2_malware_raw['zenv2_process_hollower'], True, 'zenv2_process_hollower.py'),
        ('Z2_dh_bot', z2_malware_raw['zenv2_dh_bot'], True, 'zenv2_dh_bot.py'),
        ('Z2_fragmented_dropper', z2_malware_raw['zenv2_fragmented_dropper'], True, 'zenv2_fragmented_dropper.py'),
        ('Z2_poly_cryptic', z2_malware_raw['zenv2_poly_cryptic'], True, 'zenv2_poly_cryptic.py'),
        ('Z2_covert_exfil', z2_malware_raw['zenv2_covert_exfil'], True, 'zenv2_covert_exfil.py'),
        ('Z2_reflective_loader', z2_malware_raw['zenv2_reflective_loader'], True, 'zenv2_reflective_loader.py'),
        ('Z2_hybrid_crypto', z2_malware_raw['zenv2_hybrid_crypto_beast'], True, 'zenv2_hybrid_crypto_beast.py'),
    ]
    
    # ZEN V1 MALWARE (original evasive set)
    z1_malware_raw = get_zen_malware_samples()
    z1_malware_samples = [
        ('Z1_ghost_polymorphic', z1_malware_raw['zen_ghost_polymorphic'], True, 'zen_ghost_polymorphic.py'),
        ('Z1_phantom_encoder', z1_malware_raw['zen_phantom_encoder'], True, 'zen_phantom_encoder.py'),
        ('Z1_silent_collector', z1_malware_raw['zen_silent_collector'], True, 'zen_silent_collector.py'),
        ('Z1_deep_obfuscator', z1_malware_raw['zen_deep_obfuscator'], True, 'zen_deep_obfuscator.py'),
        ('Z1_hidden_caller', z1_malware_raw['zen_hidden_caller'], True, 'zen_hidden_caller.py'),
        ('Z1_silent_persister', z1_malware_raw['zen_silent_persister'], True, 'zen_silent_persister.py'),
        ('Z1_thread_injector', z1_malware_raw['zen_thread_injector'], True, 'zen_thread_injector.py'),
        ('Z1_proc_simulator', z1_malware_raw['zen_proc_simulator'], True, 'zen_proc_simulator.py'),
        ('Z1_cryptic_locker', z1_malware_raw['zen_cryptic_locker'], True, 'zen_cryptic_locker.py'),
        ('Z1_stealth_apt', z1_malware_raw['zen_stealth_apt'], True, 'zen_stealth_apt.py'),
        ('Z1_timebomb_v2', z1_malware_raw['zen_timebomb_v2'], True, 'zen_timebomb_v2.py'),
        ('Z1_supplychain_v2', z1_malware_raw['zen_supplychain_v2'], True, 'zen_supplychain_v2.py'),
    ]
    
    # ORIGINAL SAMPLES
    orig_malware_samples = [
        ('ORIG_keylogger', get_all_samples()['malicious_keylogger'], True, 'malicious_keylogger.py'),
        ('ORIG_ransomware', get_all_samples()['malicious_ransomware'], True, 'malicious_ransomware.py'),
        ('ORIG_disguised', get_all_samples()['malicious_disguised'], True, 'malicious_disguised.py'),
        ('ORIG_polymorphic', get_advanced_samples()['advanced_polymorphic'], True, 'advanced_polymorphic.py'),
        ('ORIG_encrypted', get_advanced_samples()['advanced_encrypted'], True, 'advanced_encrypted.py'),
        ('ORIG_rootkit', get_advanced_samples()['advanced_rootkit'], True, 'advanced_rootkit.py'),
        ('ORIG_fileless', get_advanced_samples()['advanced_fileless'], True, 'advanced_fileless.py'),
        ('ORIG_apt', get_advanced_samples()['advanced_apt'], True, 'advanced_apt.py'),
    ]
    
    # ZEN CLEAN (v1 + original)
    zc_raw = get_zen_clean_samples()
    zc2_raw = get_clean_samples()
    orig_clean = get_all_samples()
    
    clean_samples = [
        ('CLE_legit_editor', orig_clean['legitimate_editor'], False, 'legitimate_program.py'),
        ('CLE_webserver', zc2_raw['clean_webserver'], False, 'clean_webserver.py'),
        ('CLE_db_backup', zc2_raw['clean_db_backup'], False, 'clean_db_backup.py'),
        ('CLE_devops_tool', zc2_raw['clean_devops_tool'], False, 'clean_devops_tool.py'),
        ('CLE_file_indexer', zc2_raw['clean_file_indexer'], False, 'clean_file_indexer.py'),
        ('CLE_system_monitor', zc2_raw['clean_system_monitor'], False, 'clean_system_monitor.py'),
        ('CLE_cloud_backup', zc_raw['zen_clean_cloudbackup'], False, 'zen_clean_cloudbackup.py'),
        ('CLE_devops', zc_raw['zen_clean_devops'], False, 'zen_clean_devops.py'),
        ('CLE_security_scanner', zc_raw['zen_clean_securityscanner'], False, 'zen_clean_securityscanner.py'),
        ('CLE_data_migrator', zc_raw['zen_clean_datamigrator'], False, 'zen_clean_datamigrator.py'),
        ('CLE_code_indexer', zc_raw['zen_clean_codeindexer'], False, 'zen_clean_codeindexer.py'),
    ]
    
    all_samples = (
        orig_malware_samples +
        z1_malware_samples +
        z2_malware_samples +
        clean_samples
    )
    
    console.print(f"\n[bold]🔬 Running {len(all_samples)} samples with Static + Runtime analysis...[/bold]\n")
    
    results = []
    skipped_runtime = 0
    
    with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), console=console) as progress:
        for name, runner, is_mal, script_file in all_samples:
            task = progress.add_task(f"[dim]{name}...[/dim]", total=None)
            
            try:
                # === PHASE 1: RUN & GENERATE CODE ===
                proc = runner(8)
                time.sleep(0.5)  # Let it start and generate code file
                
                # Read the GENERATED code (written by the runner), not the generator
                script_path = samples_dir / script_file
                code = ""
                if script_path.exists():
                    code = script_path.read_text()
                
                # === PHASE 2: STATIC ANALYSIS on generated code ===
                static_features = enhanced_static_analysis(code)
                
                # === PHASE 3: RUNTIME MONITORING ===
                runtime_score = 0
                runtime_details = {}
                
                if proc.pid:
                    try:
                        monitor = RuntimeMonitor(proc.pid, timeout=8)
                        profile = monitor.monitor()
                        runtime_score = monitor.score_runtime()
                        runtime_details = {
                            'cpu_mean': round(profile.cpu_mean, 2),
                            'cpu_max': round(profile.cpu_max, 2),
                            'cpu_spikes': profile.cpu_spikes,
                            'mem_mb': round(profile.mem_mean_mb, 2),
                            'mem_growth': round(profile.mem_growth_rate, 3),
                            'mem_volatility': round(profile.mem_volatility, 3),
                            'io_write_mb': round(profile.io_write_mb, 2),
                            'thread_max': profile.thread_max,
                            'thread_dynamic': profile.thread_dynamic,
                            'network_conns': profile.network_connections,
                            'children': profile.spawned_children,
                            'timing_regularity': round(profile.timing_regularity, 3),
                            'entropy': round(profile.entropy_score, 3),
                            'burst_events': profile.burst_events,
                        }
                    except Exception:
                        skipped_runtime += 1
                        runtime_score = 0
                
                try:
                    proc.wait(timeout=8)
                except:
                    proc.terminate()
                
                # === PHASE 3: COMBINED VERDICT ===
                verdict_info = combined_verdict(static_features, runtime_score)
                verdict = verdict_info['verdict']
                combined_net = verdict_info['combined_net']
                
                results.append({
                    'name': name,
                    'true_label': 'malicious' if is_mal else 'clean',
                    'verdict': verdict,
                    'static_net': static_features['net_threat'],
                    'static_gross': static_features['gross_threat'],
                    'runtime_score': round(runtime_score, 1),
                    'combined_net': round(combined_net, 1),
                    'features': static_features,
                    'runtime_details': runtime_details,
                })
                
                vc = '🚨' if verdict == 'malicious' else ('⚠️' if verdict == 'suspicious' else '✅')
                vcol = 'red' if verdict == 'malicious' else ('yellow' if verdict == 'suspicious' else 'green')
                console.print(f"  [{vcol}]{vc} {name}[/{vcol}] → {verdict.upper()} "
                             f"[dim](static={static_features['net_threat']:.0f}, runtime={runtime_score:.0f}, combined={combined_net:.0f})[/dim]")
                
            except Exception as e:
                console.print(f"  [red]✗ {name}: {e}[/red]")
                results.append({
                    'name': name,
                    'true_label': 'malicious' if is_mal else 'clean',
                    'verdict': 'error',
                    'static_net': 0,
                    'static_gross': 0,
                    'runtime_score': 0,
                    'combined_net': 0,
                    'features': {},
                    'runtime_details': {},
                })
            
            progress.remove_task(task)
    
    # ========================
    # RESULTS
    # ========================
    
    console.print(f"\n{'=' * 130}", style="bold red")
    console.print("[bold]📊 ZEN STRESS TEST v2.0 - FINAL RESULTS[/bold]", style="bold red")
    console.print(f"{'=' * 130}\n", style="bold red")
    
    # GROUP STATS
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
        
        return {
            'label': label,
            'total': total_mal + total_clean,
            'total_mal': total_mal,
            'total_clean': total_clean,
            'detection_rate': ((tp + sp) / total_mal * 100) if total_mal else 0,
            'strict_detection': (tp / total_mal * 100) if total_mal else 0,
            'fp_rate': (fp / total_clean * 100) if total_clean else 0,
            'fn_rate': (fn / total_mal * 100) if total_mal else 0,
            'tp': tp, 'sp': sp, 'fn': fn, 'tn': tn, 'fp': fp,
        }
    
    orig_res = [r for r in results if r['name'].startswith('ORIG_')]
    z1_res = [r for r in results if r['name'].startswith('Z1_')]
    z2_res = [r for r in results if r['name'].startswith('Z2_')]
    clean_res = [r for r in results if r['name'].startswith('CLE_')]
    
    orig_m = calc_metrics(orig_res, "Original")
    z1_m = calc_metrics(z1_res + clean_res, "Zen v1 (Evasive)")
    z2_m = calc_metrics(z2_res + clean_res, "Zen v2 (Crypto)")
    all_mal_res = orig_res + z1_res + z2_res
    all_metrics = calc_metrics(all_mal_res + clean_res, "ALL SAMPLES")
    
    # ========================
    # COMPARISON TABLE
    # ========================
    
    console.print(f"\n[bold]📈 DETECTION METRICS COMPARISON[/bold]\n")
    
    comp = Table(box=box.DOUBLE_EDGE, title="Detection Comparison Across Test Phases")
    comp.add_column("Metric", style="bold", width=20)
    comp.add_column("ORIG", style="bold cyan", width=10)
    comp.add_column("Z1 Evasive", style="bold yellow", width=12)
    comp.add_column("Z2 Crypto", style="bold red", width=12)
    comp.add_column("ALL", style="bold white", width=10)
    
    for key, name in [
        ('detection_rate', 'Detection Rate %'),
        ('strict_detection', 'Strict Detection %'),
        ('fp_rate', 'False Positives %'),
        ('fn_rate', 'False Negatives %'),
    ]:
        comp.add_row(
            name,
            f"{orig_m[key]:.1f}%",
            f"{z1_m[key]:.1f}%",
            f"{z2_m[key]:.1f}%",
            f"{all_metrics[key]:.1f}%",
        )
    
    console.print(comp)
    
    # ========================
    # COUNT TABLE
    # ========================
    
    console.print(f"\n[bold]📊 COUNT BREAKDOWN[/bold]\n")
    
    counts = Table(box=box.SIMPLE)
    counts.add_column("", style="bold", width=22)
    counts.add_column("ORIG", width=8)
    counts.add_column("Z1", width=8)
    counts.add_column("Z2", width=8)
    counts.add_column("ALL", width=8)
    
    for key, name in [
        ('total_mal', 'Total Malware'),
        ('tp', 'True Positives'),
        ('sp', 'Suspicious'),
        ('fn', 'False Negatives ❌'),
        ('total_clean', 'Total Clean'),
        ('tn', 'True Negatives'),
        ('fp', 'False Positives ❌'),
    ]:
        counts.add_row(
            name,
            str(orig_m[key]),
            str(z1_m[key]),
            str(z2_m[key]),
            str(all_metrics[key]),
        )
    
    console.print(counts)
    
    # ========================
    # RUNTIME DETAILS
    # ========================
    
    console.print(f"\n[bold]⚡ RUNTIME BEHAVIORAL ANALYSIS DETAILS[/bold]\n")
    
    rt = Table(box=box.SIMPLE, title="Runtime Metrics (Top Samples)")
    rt.add_column("Sample", style="bold", width=25)
    rt.add_column("CPU", width=6)
    rt.add_column("Spikes", width=6)
    rt.add_column("Mem MB", width=7)
    rt.add_column("IOw MB", width=7)
    rt.add_column("Thr", width=4)
    rt.add_column("Net", width=4)
    rt.add_column("Child", width=5)
    rt.add_column("Entropy", width=7)
    rt.add_column("Regular", width=7)
    rt.add_column("R-Score", width=7)
    
    for r in sorted(results, key=lambda x: x.get('runtime_score', 0), reverse=True)[:20]:
        d = r.get('runtime_details', {})
        if d:
            rt.add_row(
                r['name'],
                f"{d.get('cpu_max', 0):.0f}",
                str(d.get('cpu_spikes', 0)),
                f"{d.get('mem_mb', 0):.1f}",
                f"{d.get('io_write_mb', 0):.1f}",
                str(d.get('thread_max', 0)),
                str(d.get('network_conns', 0)),
                str(d.get('children', 0)),
                f"{d.get('entropy', 0):.3f}",
                f"{d.get('timing_regularity', 0):.3f}",
                f"{r.get('runtime_score', 0):.0f}",
            )
    
    console.print(rt)
    
    # ========================
    # VULNERABILITY ANALYSIS
    # ========================
    
    console.print(f"\n[bold red]🔴 VULNERABILITY REPORT[/bold red]\n")
    
    # Z2 misses
    z2_mal = [r for r in z2_res if r['true_label'] == 'malicious']
    z2_missed = [r for r in z2_mal if r['verdict'] == 'clean']
    z2_partial = [r for r in z2_mal if r['verdict'] == 'suspicious']
    z2_caught = [r for r in z2_mal if r['verdict'] == 'malicious']
    
    console.print(f"[bold]Zen v2 Crypto Malware (15 samples):[/bold]")
    console.print(f"  🚨 Full detection: [green]{len(z2_caught)}[/green]")
    console.print(f"  ⚠️ Suspicious only: [yellow]{len(z2_partial)}[/yellow]")
    console.print(f"  ❌ Missed completely: [red]{len(z2_missed)}[/red]")
    
    if z2_missed:
        for r in z2_missed:
            console.print(f"    • {r['name']} → CLEAN (rt={r['runtime_score']:.0f}, st={r['static_net']:.0f})")
    if z2_partial:
        for r in z2_partial:
            console.print(f"    • {r['name']} → SUSPICIOUS (rt={r['runtime_score']:.0f}, st={r['static_net']:.0f})")
    
    # False positives
    fp_samples = [r for r in clean_res if r['verdict'] != 'clean']
    if fp_samples:
        console.print(f"\n[red]⚠️ FALSE POSITIVES ({len(fp_samples)}):[/red]")
        for r in fp_samples:
            console.print(f"  • {r['name']} → {r['verdict'].upper()}")
    else:
        console.print(f"\n[green]✅ ZERO False Positives on clean programs[/green]")
    
    # ========================
    # SAVE REPORT
    # ========================
    
    report_data = {
        'experiment': 'Zen Stress Test v2.0 - Static + Runtime Combined Analysis',
        'timestamp': time.time(),
        'total_samples': len(results),
        'methodology': {
            'static_analysis': 'Enhanced 11-layer + evasion detection',
            'runtime_analysis': 'psutil-based: CPU, memory, I/O, threads, network, children',
            'verdict_logic': '55% static + 45% runtime weighted combination',
        },
        'metrics': {
            'original': orig_m,
            'zen_v1': z1_m,
            'zen_v2': z2_m,
            'all': all_metrics,
        },
        'crypto_techniques_tested': [
            'AES-256-CBC (pure Python)',
            'ChaCha20 stream cipher',
            'Fernet-like symmetric encryption',
            'Rot13 + Hex + Base64 multi-layer',
            'XOR with 5 rotating keys',
            'Diffie-Hellman key exchange',
            'marshal bytecode serialization',
            'zlib compression (level 9)',
            'base85 encoding',
            'HMAC-SHA256 integrity',
            'PBKDF2-inspired key derivation',
            'Self-modifying polymorphic cipher selection',
        ],
        'all_results': results,
    }
    
    report_path = Path(__file__).parent.parent / "reports" / f"zen_stress_test_v2_{int(time.time())}.json"
    report_path.parent.mkdir(exist_ok=True)
    with open(report_path, 'w', encoding='utf-8') as f:
        json.dump(report_data, f, indent=2, ensure_ascii=False, default=str)
    
    console.print(f"\n[green]✓ Full report: {report_path}[/green]\n")
    
    # ========================
    # FINAL SCORECARD
    # ========================
    
    console.print("=" * 80, style="bold red")
    console.print("[bold red]🏆 FINAL SCORECARD[/bold red]")
    console.print(f"[bold]Total Samples: {len(results)} | Malware: {all_metrics['total_mal']} | Clean: {all_metrics['total_clean']}[/bold]")
    console.print(f"[bold]Overall Detection: {all_metrics['detection_rate']:.1f}% | Strict: {all_metrics['strict_detection']:.1f}%[/bold]")
    console.print(f"[bold]False Negatives: {all_metrics['fn_rate']:.1f}% | False Positives: {all_metrics['fp_rate']:.1f}%[/bold]")
    console.print("=" * 80, style="bold red")
    
    return results


if __name__ == "__main__":
    try:
        run_zen_stress_test_v2()
    except KeyboardInterrupt:
        print("\n⚠️ Interrupted\n")
    except Exception as e:
        print(f"\n❌ Error: {e}\n")
        import traceback
        traceback.print_exc()
