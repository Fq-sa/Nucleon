"""
Main Test Runner - نقطة التشغيل الرئيسية للاختبار
"""
import sys
import time
from pathlib import Path
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn

# إضافة المسار الجذر
sys.path.insert(0, str(Path(__file__).parent.parent))

from dna_engine.simulation_engine import SimulationEngine
from dna_engine.samples.test_samples import get_all_samples
from dna_engine.samples.advanced_malware import get_advanced_samples
from dna_engine.results_reporter import ResultsReporter


def run_test():
    """تشغيل الاختبار الكامل بمرحلتين: جمع ثم تحليل"""
    console = Console()
    reporter = ResultsReporter()
    engine = SimulationEngine()
    
    # عرض الرأس
    reporter.display_header()
    
    # جمع جميع العينات
    basic_samples = get_all_samples()
    advanced_samples = get_advanced_samples()
    
    all_samples = {
        'legitimate_editor': (basic_samples['legitimate_editor'], False),
        'malicious_keylogger': (basic_samples['malicious_keylogger'], True),
        'malicious_ransomware': (basic_samples['malicious_ransomware'], True),
        'malicious_disguised': (basic_samples['malicious_disguised'], True),
        'advanced_polymorphic': (advanced_samples['advanced_polymorphic'], True),
        'advanced_encrypted': (advanced_samples['advanced_encrypted'], True),
        'advanced_rootkit': (advanced_samples['advanced_rootkit'], True),
        'advanced_fileless': (advanced_samples['advanced_fileless'], True),
        'advanced_apt': (advanced_samples['advanced_apt'], True),
        'advanced_zeroday': (advanced_samples['advanced_zeroday'], True),
    }
    
    # المرحلة 1: جمع جميع البصمات أولاً
    console.print(f"\n[bold cyan]🔬 المرحلة 1: جمع البصمات السلوكية لـ {len(all_samples)} عينة...[/bold cyan]\n")
    
    fingerprints = {}
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console
    ) as progress:
        for program_name, (runner, is_malicious) in all_samples.items():
            task = progress.add_task(f"تشغيل {program_name}...", total=None)
            try:
                process = runner(8)
                analysis = engine.analyze_program(process, program_name, duration=8)
                fingerprint = analysis['fingerprint']
                
                # إضافة البصمة لقاعدة البيانات
                engine.database.add_signature(program_name, fingerprint, is_malicious)
                fingerprints[program_name] = {
                    'fingerprint': fingerprint,
                    'is_malicious': is_malicious,
                    'analysis': analysis
                }
                console.print(f"  [dim]✓ تم جمع بصمة {program_name}[/dim]")
            except Exception as e:
                console.print(f"  [red]❌ خطأ في {program_name}: {e}[/red]")
            progress.remove_task(task)
    
    # المرحلة 2: مقارنة كل عينة مع كامل قاعدة البيانات
    console.print(f"\n[bold cyan]🔬 المرحلة 2: تحليل ومقارنة البصمات...[/bold cyan]\n")
    
    results = []
    for program_name, data in fingerprints.items():
        comparison = engine.compare_with_database(data['fingerprint'], program_name)
        
        result = {
            'program_name': program_name,
            'is_known_malicious': data['is_malicious'],
            'analysis': data['analysis'],
            'comparison': comparison,
            'timestamp': time.time()
        }
        results.append(result)
        
        verdict = comparison['verdict']
        if verdict == 'malicious':
            console.print(f"  [red]🚨 {program_name}: خبيث[/red]")
        elif verdict == 'suspicious':
            console.print(f"  [yellow]⚠️  {program_name}: مشبوه[/yellow]")
        else:
            console.print(f"  [green]✅ {program_name}: نظيف[/green]")
    
    # عرض النتائج التفصيلية
    console.print(f"\n{'=' * 60}", style="bold cyan")
    console.print("[bold]📋 النتائج التفصيلية[/bold]", style="bold cyan")
    console.print(f"{'=' * 60}", style="bold cyan")
    
    for result in results:
        reporter.display_sample_result(result)
    
    # عرض الملخص
    reporter.display_summary(results)
    
    # حفظ التقرير
    reporter.save_report(results)
    
    return results


if __name__ == "__main__":
    try:
        run_test()
    except KeyboardInterrupt:
        print("\n\n[yellow]⚠️ تم إيقاف الاختبار[/yellow]\n")
    except Exception as e:
        print(f"\n[red]❌ خطأ: {e}[/red]\n")
        import traceback
        traceback.print_exc()
