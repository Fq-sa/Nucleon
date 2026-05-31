"""
Results Reporter - واجهة عرض النتائج والتقارير
"""
import json
from pathlib import Path
from datetime import datetime
from typing import Dict, List
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich.columns import Columns
from rich import box


class ResultsReporter:
    def __init__(self):
        self.console = Console()
        
    def display_header(self):
        """عرض رأس التقرير"""
        self.console.print("\n")
        title = Text("🧬 Behavioral DNA Analysis Report", style="bold cyan")
        subtitle = Text("تقرير تحليل الحمض النووي السلوكي", style="dim")
        
        self.console.print(Panel(
            f"{title}\n{subtitle}",
            border_style="cyan",
            padding=(1, 2)
        ))
        self.console.print()
        
    def display_sample_result(self, result: Dict):
        """عرض نتيجة عينة واحدة"""
        program_name = result['program_name']
        is_known_malicious = result['is_known_malicious']
        verdict = result['comparison']['verdict']
        
        # تحديد اللون بناءً على النتيجة
        if verdict == 'malicious':
            status_color = "red"
            status_icon = "🚨"
            status_text = "MALICIOUS - خبيث"
        elif verdict == 'suspicious':
            status_color = "yellow"
            status_icon = "⚠️"
            status_text = "SUSPICIOUS - مشبوه"
        else:
            status_color = "green"
            status_icon = "✅"
            status_text = "CLEAN - نظيف"
        
        # عنوان العينة
        self.console.print(f"\n{'─' * 60}", style="dim")
        self.console.print(f"{status_icon} {program_name}", style=f"bold {status_color}")
        self.console.print(f"{'─' * 60}\n", style="dim")
        
        # معلومات أساسية
        info_table = Table(show_header=False, box=None, padding=(0, 2))
        info_table.add_column("Label", style="dim")
        info_table.add_column("Value", style="bold")
        
        info_table.add_row("الحالة المعروفة:", 
                          "خبيث" if is_known_malicious else "نظيف")
        info_table.add_row("الحكم:", status_text)
        info_table.add_row("التوقيت:", 
                          datetime.fromtimestamp(result['timestamp']).strftime('%Y-%m-%d %H:%M:%S'))
        
        self.console.print(info_table)
        
        # أفضل تطابق
        best_match = result['comparison'].get('best_match')
        if best_match:
            self.console.print("\n[bold]أفضل تطابق:[/bold]")
            match_table = Table(box=box.SIMPLE)
            match_table.add_column("البرنامج", style="cyan")
            match_table.add_column("التشابه", style="magenta")
            match_table.add_column("الحالة", style="yellow")
            
            match_table.add_row(
                best_match['compared_with'],
                f"{best_match['similarity']:.3f}",
                "خبيث" if best_match['is_known_malicious'] else "نظيف"
            )
            self.console.print(match_table)
        
        # تفاصيل التشابه
        similarities = result['comparison'].get('all_comparisons', [])
        if similarities:
            self.console.print(f"\n[bold]جميع المقارنات ({len(similarities)}):[/bold]")
            comp_table = Table(box=box.ROUNDED)
            comp_table.add_column("#", style="dim")
            comp_table.add_column("البرنامج", style="cyan")
            comp_table.add_column("التشابه", style="magenta")
            comp_table.add_column("خبيث", style="yellow")
            comp_table.add_column("الحكم", style="green")
            
            for i, comp in enumerate(similarities[:5], 1):
                verdict_icon = "✅" if comp['similarity'] < 0.75 else "❌"
                comp_table.add_row(
                    str(i),
                    comp['compared_with'],
                    f"{comp['similarity']:.3f}",
                    "نعم" if comp['is_known_malicious'] else "لا",
                    verdict_icon
                )
            
            self.console.print(comp_table)
        
        self.console.print()
        
    def display_summary(self, results: List[Dict]):
        """عرض الملخص النهائي"""
        self.console.print(f"\n{'=' * 60}", style="bold cyan")
        self.console.print("[bold]📊 الملخص النهائي[/bold]", style="bold cyan")
        self.console.print(f"{'=' * 60}\n", style="bold cyan")
        
        # إحصائيات عامة
        total = len(results)
        malicious_detected = sum(1 for r in results if r['comparison']['verdict'] == 'malicious')
        suspicious_detected = sum(1 for r in results if r['comparison']['verdict'] == 'suspicious')
        clean = sum(1 for r in results if r['comparison']['verdict'] == 'clean')
        
        stats_table = Table(box=box.DOUBLE_EDGE)
        stats_table.add_column("المقياس", style="bold")
        stats_table.add_column("القيمة", style="bold cyan")
        stats_table.add_column("النسبة", style="bold magenta")
        
        stats_table.add_row("إجمالي العينات", str(total), "100%")
        stats_table.add_row("تم اكتشافها كخبيثة", str(malicious_detected), 
                          f"{malicious_detected/total*100:.1f}%" if total > 0 else "0%")
        stats_table.add_row("مشبوهة", str(suspicious_detected), 
                          f"{suspicious_detected/total*100:.1f}%" if total > 0 else "0%")
        stats_table.add_row("نظيفة", str(clean), 
                          f"{clean/total*100:.1f}%" if total > 0 else "0%")
        
        self.console.print(stats_table)
        
        # دقة الاكتشاف
        self.console.print("\n[bold]🎯 دقة الاكتشاف:[/bold]")
        
        true_positives = sum(1 for r in results if r['is_known_malicious'] and r['comparison']['verdict'] == 'malicious')
        false_positives = sum(1 for r in results if not r['is_known_malicious'] and r['comparison']['verdict'] == 'malicious')
        true_negatives = sum(1 for r in results if not r['is_known_malicious'] and r['comparison']['verdict'] == 'clean')
        false_negatives = sum(1 for r in results if r['is_known_malicious'] and r['comparison']['verdict'] == 'clean')
        
        accuracy_table = Table(box=box.SIMPLE)
        accuracy_table.add_column("المقياس", style="dim")
        accuracy_table.add_column("القيمة", style="bold green")
        
        total_malicious = sum(1 for r in results if r['is_known_malicious'])
        total_clean = sum(1 for r in results if not r['is_known_malicious'])
        
        detection_rate = (true_positives / total_malicious * 100) if total_malicious > 0 else 0
        false_positive_rate = (false_positives / total_clean * 100) if total_clean > 0 else 0
        
        accuracy_table.add_row("إجمالي الخبيثة المعروفة", str(total_malicious))
        accuracy_table.add_row("إجمالي النظيفة المعروفة", str(total_clean))
        accuracy_table.add_row("True Positives (اكتشاف صحيح)", str(true_positives))
        accuracy_table.add_row("False Negatives (فشل اكتشاف)", str(false_negatives))
        accuracy_table.add_row("True Negatives (نظيف صحيح)", str(true_negatives))
        accuracy_table.add_row("False Positives (إنذار كاذب)", str(false_positives))
        accuracy_table.add_row("", "")
        accuracy_table.add_row("[bold]معدل الاكتشاف[/bold]", 
                              f"[bold]{detection_rate:.1f}%[/bold]")
        accuracy_table.add_row("[bold]معدل الإنذارات الكاذبة[/bold]", 
                              f"[bold]{false_positive_rate:.1f}%[/bold]")
        
        self.console.print(accuracy_table)
        
        # الحكم النهائي
        self.console.print("\n" + "=" * 60, style="bold cyan")
        if detection_rate >= 80:
            verdict_text = "✅ ممتاز! المحرك اكتشف معظم الفايروسات المتقدمة"
            verdict_color = "green"
        elif detection_rate >= 60:
            verdict_text = "⚠️ جيد، لكن يحتاج تحسين"
            verdict_color = "yellow"
        else:
            verdict_text = "❌ ضعيف، المحرك فشل في اكتشاف الفايروسات"
            verdict_color = "red"
        
        self.console.print(f"[bold {verdict_color}]{verdict_text}[/bold {verdict_color}]")
        self.console.print("=" * 60 + "\n", style="bold cyan")
        
    def save_report(self, results: List[Dict], filename: str = None):
        """حفظ التقرير كملف JSON"""
        if filename is None:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = f"dna_report_{timestamp}.json"
        
        report_path = Path(__file__).parent.parent / "reports" / filename
        report_path.parent.mkdir(exist_ok=True)
        
        with open(report_path, 'w', encoding='utf-8') as f:
            json.dump(results, f, indent=2, ensure_ascii=False, default=str)
        
        self.console.print(f"\n[green]✓ تم حفظ التقرير في:[/green] {report_path}\n")
