import customtkinter as ctk
from tkinter import filedialog, messagebox
import threading
from pathlib import Path
from core.file_scanner import FileScanner
from core.network_monitor import NetworkMonitor
from core.firewall import Firewall
from core.process_scanner import ProcessScanner
from utils.logger import logger

ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")

class SecurityApp(ctk.CTk):
    def __init__(self):
        super().__init__()
        
        self.title("KuraTi Security - حماية شاملة")
        self.geometry("1200x800")
        self.minsize(1000, 700)
        
        self.file_scanner = FileScanner()
        self.network_monitor = NetworkMonitor()
        self.firewall = Firewall()
        self.process_scanner = ProcessScanner()
        
        self.scanning = False
        
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)
        
        self.create_sidebar()
        self.create_main_content()
        
        self.show_dashboard()
    
    def create_sidebar(self):
        self.sidebar = ctk.CTkFrame(self, width=250, corner_radius=0)
        self.sidebar.grid(row=0, column=0, sticky="nsw")
        self.sidebar.grid_propagate(False)
        
        title = ctk.CTkLabel(
            self.sidebar, 
            text="🛡️ KuraTi Security",
            font=ctk.CTkFont(size=20, weight="bold")
        )
        title.pack(pady=20)
        
        self.btn_dashboard = ctk.CTkButton(
            self.sidebar, 
            text="لوحة التحكم",
            command=self.show_dashboard,
            height=40
        )
        self.btn_dashboard.pack(pady=5, padx=20, fill="x")
        
        self.btn_file_scan = ctk.CTkButton(
            self.sidebar,
            text="فحص الملفات",
            command=self.show_file_scanner,
            height=40
        )
        self.btn_file_scan.pack(pady=5, padx=20, fill="x")
        
        self.btn_network = ctk.CTkButton(
            self.sidebar,
            text="مراقبة الشبكة",
            command=self.show_network_monitor,
            height=40
        )
        self.btn_network.pack(pady=5, padx=20, fill="x")
        
        self.btn_firewall = ctk.CTkButton(
            self.sidebar,
            text="الجدار الناري",
            command=self.show_firewall,
            height=40
        )
        self.btn_firewall.pack(pady=5, padx=20, fill="x")
        
        self.btn_processes = ctk.CTkButton(
            self.sidebar,
            text="فحص العمليات",
            command=self.show_processes,
            height=40
        )
        self.btn_processes.pack(pady=5, padx=20, fill="x")
    
    def create_main_content(self):
        self.main_content = ctk.CTkFrame(self, corner_radius=0)
        self.main_content.grid(row=0, column=1, sticky="nsew", padx=10, pady=10)
        self.main_content.grid_columnconfigure(0, weight=1)
        self.main_content.grid_rowconfigure(0, weight=1)
    
    def clear_content(self):
        for widget in self.main_content.winfo_children():
            widget.destroy()
    
    def show_dashboard(self):
        self.clear_content()
        
        dashboard = ctk.CTkFrame(self.main_content)
        dashboard.grid(row=0, column=0, sticky="nsew", padx=20, pady=20)
        dashboard.grid_columnconfigure((0, 1, 2, 3), weight=1)
        
        title = ctk.CTkLabel(
            dashboard,
            text="لوحة التحكم الرئيسية",
            font=ctk.CTkFont(size=28, weight="bold")
        )
        title.grid(row=0, column=0, columnspan=4, pady=20)
        
        stats_frame = ctk.CTkFrame(dashboard)
        stats_frame.grid(row=1, column=0, columnspan=4, sticky="ew", pady=10)
        stats_frame.grid_columnconfigure((0, 1, 2, 3), weight=1)
        
        self.create_stat_card(stats_frame, 0, "الملفات المفحوصة", "0", "files")
        self.create_stat_card(stats_frame, 1, "التهديدات", "0", "threats")
        self.create_stat_card(stats_frame, 2, "اتصالات الشبكة", "0", "network")
        self.create_stat_card(stats_frame, 3, "العمليات النشطة", "0", "processes")
        
        status_frame = ctk.CTkFrame(dashboard)
        status_frame.grid(row=2, column=0, columnspan=4, sticky="nsew", pady=10)
        status_frame.grid_columnconfigure(0, weight=1)
        status_frame.grid_rowconfigure(0, weight=1)
        
        self.status_text = ctk.CTkTextbox(status_frame, height=300)
        self.status_text.grid(row=0, column=0, sticky="nsew", padx=10, pady=10)
        self.status_text.insert("1.0", "مرحباً بك في KuraTi Security\n\n")
        self.status_text.insert("end", "النظام جاهز للحماية\n")
        self.status_text.insert("end", "استخدم القائمة الجانبية للتنقل بين الأدوات\n")
        self.status_text.configure(state="disabled")
    
    def create_stat_card(self, parent, col, title, value, icon):
        card = ctk.CTkFrame(parent)
        card.grid(row=0, column=col, padx=10, pady=10, sticky="nsew")
        
        icon_label = ctk.CTkLabel(card, text=self.get_icon(icon), font=ctk.CTkFont(size=32))
        icon_label.pack(pady=10)
        
        title_label = ctk.CTkLabel(card, text=title, font=ctk.CTkFont(size=14))
        title_label.pack()
        
        value_label = ctk.CTkLabel(
            card, 
            text=value, 
            font=ctk.CTkFont(size=24, weight="bold")
        )
        value_label.pack(pady=5)
    
    def get_icon(self, name):
        icons = {
            "files": "📁",
            "threats": "⚠️",
            "network": "🌐",
            "processes": "⚙️"
        }
        return icons.get(name, "📊")
    
    def show_file_scanner(self):
        self.clear_content()
        
        frame = ctk.CTkFrame(self.main_content)
        frame.grid(row=0, column=0, sticky="nsew", padx=20, pady=20)
        frame.grid_columnconfigure(0, weight=1)
        
        title = ctk.CTkLabel(
            frame,
            text="فحص الملفات",
            font=ctk.CTkFont(size=24, weight="bold")
        )
        title.grid(row=0, column=0, pady=20)
        
        path_frame = ctk.CTkFrame(frame)
        path_frame.grid(row=1, column=0, sticky="ew", pady=10)
        path_frame.grid_columnconfigure(1, weight=1)
        
        self.path_var = ctk.StringVar(value="اختر مجلد أو ملف...")
        path_entry = ctk.CTkEntry(path_frame, textvariable=self.path_var, height=40)
        path_entry.grid(row=0, column=0, columnspan=2, sticky="ew", padx=10, pady=10)
        
        browse_btn = ctk.CTkButton(
            path_frame,
            text="تصفح",
            command=self.browse_path,
            width=100
        )
        browse_btn.grid(row=0, column=2, padx=10, pady=10)
        
        btn_frame = ctk.CTkFrame(frame)
        btn_frame.grid(row=2, column=0, pady=10)
        
        self.scan_btn = ctk.CTkButton(
            btn_frame,
            text="بدء الفحص",
            command=self.start_scan,
            height=40,
            width=150
        )
        self.scan_btn.pack(side="left", padx=10)
        
        stop_btn = ctk.CTkButton(
            btn_frame,
            text="إيقاف",
            command=self.stop_scan,
            height=40,
            width=150,
            fg_color="red",
            hover_color="darkred"
        )
        stop_btn.pack(side="left", padx=10)
        
        self.progress = ctk.CTkProgressBar(frame)
        self.progress.grid(row=3, column=0, sticky="ew", padx=10, pady=10)
        self.progress.set(0)
        
        self.progress_label = ctk.CTkLabel(frame, text="جاهز")
        self.progress_label.grid(row=4, column=0, pady=5)
        
        results_frame = ctk.CTkFrame(frame)
        results_frame.grid(row=5, column=0, sticky="nsew", pady=10)
        results_frame.grid_columnconfigure(0, weight=1)
        results_frame.grid_rowconfigure(0, weight=1)
        
        self.results_text = ctk.CTkTextbox(results_frame, height=300)
        self.results_text.grid(row=0, column=0, sticky="nsew", padx=10, pady=10)
        self.results_text.insert("1.0", "نتائج الفحص ستظهر هنا...\n")
        self.results_text.configure(state="disabled")
        
        frame.grid_rowconfigure(5, weight=1)
    
    def browse_path(self):
        path = filedialog.askdirectory(title="اختر مجلد للفحص")
        if path:
            self.path_var.set(path)
    
    def start_scan(self):
        path = Path(self.path_var.get())
        if not path.exists():
            messagebox.showerror("خطأ", "المسار غير موجود")
            return
        
        self.scanning = True
        self.scan_btn.configure(state="disabled")
        self.results_text.configure(state="normal")
        self.results_text.delete("1.0", "end")
        self.results_text.insert("1.0", "جاري الفحص...\n\n")
        self.results_text.configure(state="disabled")
        
        thread = threading.Thread(target=self._scan_thread, args=(path,), daemon=True)
        thread.start()
    
    def _scan_thread(self, path):
        def progress_callback(current, total, file_path):
            progress = current / total
            self.after(0, lambda: self.update_progress(progress, f"فحص: {Path(file_path).name}"))
        
        def should_cancel():
            return not self.scanning
        
        results = self.file_scanner.scan_directory(
            path,
            progress_callback=progress_callback,
            cancel_flag=should_cancel
        )
        
        self.after(0, lambda: self.display_results(results))
    
    def stop_scan(self):
        self.scanning = False
        self.scan_btn.configure(state="normal")
        self.progress_label.configure(text="تم الإيقاف")
    
    def update_progress(self, value, text):
        self.progress.set(value)
        self.progress_label.configure(text=text)
    
    def display_results(self, results):
        self.scanning = False
        self.scan_btn.configure(state="normal")
        self.progress.set(1.0)
        
        summary = self.file_scanner.get_summary()
        
        self.results_text.configure(state="normal")
        self.results_text.delete("1.0", "end")
        self.results_text.insert("1.0", f"=== ملخص الفحص ===\n")
        self.results_text.insert("end", f"إجمالي الملفات: {summary['total']}\n")
        self.results_text.insert("end", f"ملفات نظيفة: {summary['clean']}\n")
        self.results_text.insert("end", f"تهديدات: {summary['malicious']}\n")
        self.results_text.insert("end", f"أخطاء: {summary['errors']}\n\n")
        
        self.results_text.insert("end", "=== التهديدات المكتشفة ===\n\n")
        
        for result in results:
            if result["status"] == "malicious":
                self.results_text.insert("end", f"⚠️ {result['name']}\n")
                self.results_text.insert("end", f"   المسار: {result['path']}\n")
                self.results_text.insert("end", f"   التهديدات: {', '.join(result['threats'])}\n\n")
        
        self.results_text.configure(state="disabled")
        self.progress_label.configure(text="اكتمل الفحص")
    
    def show_network_monitor(self):
        self.clear_content()
        
        frame = ctk.CTkFrame(self.main_content)
        frame.grid(row=0, column=0, sticky="nsew", padx=20, pady=20)
        frame.grid_columnconfigure(0, weight=1)
        
        title = ctk.CTkLabel(
            frame,
            text="مراقبة الشبكة",
            font=ctk.CTkFont(size=24, weight="bold")
        )
        title.grid(row=0, column=0, pady=20)
        
        btn_frame = ctk.CTkFrame(frame)
        btn_frame.grid(row=1, column=0, pady=10)
        
        refresh_btn = ctk.CTkButton(
            btn_frame,
            text="تحديث",
            command=self.refresh_network,
            height=40,
            width=150
        )
        refresh_btn.pack(side="left", padx=10)
        
        stats_frame = ctk.CTkFrame(frame)
        stats_frame.grid(row=2, column=0, sticky="ew", pady=10)
        stats_frame.grid_columnconfigure((0, 1, 2, 3), weight=1)
        
        self.net_stats = {}
        self.net_stats['sent'] = ctk.CTkLabel(stats_frame, text="المرسل: 0 بايت")
        self.net_stats['sent'].grid(row=0, column=0, padx=10, pady=10)
        
        self.net_stats['recv'] = ctk.CTkLabel(stats_frame, text="المستقبل: 0 بايت")
        self.net_stats['recv'].grid(row=0, column=1, padx=10, pady=10)
        
        self.net_stats['packets'] = ctk.CTkLabel(stats_frame, text="الحزم: 0")
        self.net_stats['packets'].grid(row=0, column=2, padx=10, pady=10)
        
        self.net_stats['errors'] = ctk.CTkLabel(stats_frame, text="الأخطاء: 0")
        self.net_stats['errors'].grid(row=0, column=3, padx=10, pady=10)
        
        connections_frame = ctk.CTkFrame(frame)
        connections_frame.grid(row=3, column=0, sticky="nsew", pady=10)
        connections_frame.grid_columnconfigure(0, weight=1)
        connections_frame.grid_rowconfigure(0, weight=1)
        
        self.connections_text = ctk.CTkTextbox(connections_frame, height=400)
        self.connections_text.grid(row=0, column=0, sticky="nsew", padx=10, pady=10)
        self.connections_text.insert("1.0", "اضغط 'تحديث' لعرض الاتصالات...\n")
        self.connections_text.configure(state="disabled")
        
        frame.grid_rowconfigure(3, weight=1)
        
        self.refresh_network()
    
    def refresh_network(self):
        connections = self.network_monitor.get_connections()
        stats = self.network_monitor.get_stats()
        
        self.net_stats['sent'].configure(text=f"المرسل: {stats.get('bytes_sent', 0):,} بايت")
        self.net_stats['recv'].configure(text=f"المستقبل: {stats.get('bytes_recv', 0):,} بايت")
        self.net_stats['packets'].configure(text=f"الحزم: {stats.get('packets_sent', 0) + stats.get('packets_recv', 0):,}")
        self.net_stats['errors'].configure(text=f"الأخطاء: {stats.get('errors_in', 0) + stats.get('errors_out', 0):,}")
        
        self.connections_text.configure(state="normal")
        self.connections_text.delete("1.0", "end")
        self.connections_text.insert("1.0", f"=== الاتصالات النشطة ({len(connections)}) ===\n\n")
        
        suspicious = self.network_monitor.get_suspicious_connections()
        if suspicious:
            self.connections_text.insert("end", f"⚠️ اتصالات مشبوهة: {len(suspicious)}\n\n")
            for conn in suspicious:
                self.connections_text.insert("end", f"🔴 {conn['local_address']} -> {conn['remote_address']}\n")
                self.connections_text.insert("end", f"   العملية: {conn['process']} | الحالة: {conn['status']}\n")
                self.connections_text.insert("end", f"   السبب: {conn.get('reason', 'غير محدد')}\n\n")
            
            self.connections_text.insert("end", "\n")
        
        self.connections_text.insert("end", "=== جميع الاتصالات ===\n\n")
        for conn in connections[:50]:
            status_icon = "🔴" if conn.get("suspicious") else "🟢"
            self.connections_text.insert("end", f"{status_icon} {conn['local_address']} -> {conn['remote_address']}\n")
            self.connections_text.insert("end", f"   {conn['process']} | {conn['status']} | {conn['type']}\n")
        
        self.connections_text.configure(state="disabled")
    
    def show_firewall(self):
        self.clear_content()
        
        frame = ctk.CTkFrame(self.main_content)
        frame.grid(row=0, column=0, sticky="nsew", padx=20, pady=20)
        frame.grid_columnconfigure(0, weight=1)
        
        title = ctk.CTkLabel(
            frame,
            text="الجدار الناري",
            font=ctk.CTkFont(size=24, weight="bold")
        )
        title.grid(row=0, column=0, pady=20)
        
        input_frame = ctk.CTkFrame(frame)
        input_frame.grid(row=1, column=0, sticky="ew", pady=10)
        input_frame.grid_columnconfigure(1, weight=1)
        
        ctk.CTkLabel(input_frame, text="عنوان IP:").grid(row=0, column=0, padx=10, pady=10)
        
        self.ip_entry = ctk.CTkEntry(input_frame, height=40, placeholder_text="192.168.1.100")
        self.ip_entry.grid(row=0, column=1, sticky="ew", padx=10, pady=10)
        
        block_btn = ctk.CTkButton(
            input_frame,
            text="حظر",
            command=self.block_ip,
            width=100,
            fg_color="red",
            hover_color="darkred"
        )
        block_btn.grid(row=0, column=2, padx=10, pady=10)
        
        unblock_btn = ctk.CTkButton(
            input_frame,
            text="إلغاء الحظر",
            command=self.unblock_ip,
            width=100
        )
        unblock_btn.grid(row=0, column=3, padx=10, pady=10)
        
        list_frame = ctk.CTkFrame(frame)
        list_frame.grid(row=2, column=0, sticky="nsew", pady=10)
        list_frame.grid_columnconfigure(0, weight=1)
        list_frame.grid_rowconfigure(0, weight=1)
        
        self.blocked_text = ctk.CTkTextbox(list_frame, height=400)
        self.blocked_text.grid(row=0, column=0, sticky="nsew", padx=10, pady=10)
        
        frame.grid_rowconfigure(2, weight=1)
        
        self.refresh_blocked_list()
    
    def block_ip(self):
        ip = self.ip_entry.get().strip()
        if not ip:
            messagebox.showwarning("تحذير", "الرجاء إدخال عنوان IP")
            return
        
        result = self.firewall.block_ip(ip)
        if result["success"]:
            messagebox.showinfo("نجاح", f"تم حظر {ip}")
            self.refresh_blocked_list()
        else:
            messagebox.showerror("خطأ", result["message"])
    
    def unblock_ip(self):
        ip = self.ip_entry.get().strip()
        if not ip:
            messagebox.showwarning("تحذير", "الرجاء إدخال عنوان IP")
            return
        
        result = self.firewall.unblock_ip(ip)
        if result["success"]:
            messagebox.showinfo("نجاح", f"تم إلغاء حظر {ip}")
            self.refresh_blocked_list()
        else:
            messagebox.showerror("خطأ", result["message"])
    
    def refresh_blocked_list(self):
        blocked = self.firewall.get_blocked_list()
        
        self.blocked_text.configure(state="normal")
        self.blocked_text.delete("1.0", "end")
        self.blocked_text.insert("1.0", f"=== عناوين IP المحظورة ({len(blocked)}) ===\n\n")
        
        for ip in blocked:
            self.blocked_text.insert("end", f"🚫 {ip}\n")
        
        if not blocked:
            self.blocked_text.insert("end", "لا توجد عناوين محظورة حالياً\n")
        
        self.blocked_text.configure(state="disabled")
    
    def show_processes(self):
        self.clear_content()
        
        frame = ctk.CTkFrame(self.main_content)
        frame.grid(row=0, column=0, sticky="nsew", padx=20, pady=20)
        frame.grid_columnconfigure(0, weight=1)
        
        title = ctk.CTkLabel(
            frame,
            text="فحص العمليات",
            font=ctk.CTkFont(size=24, weight="bold")
        )
        title.grid(row=0, column=0, pady=20)
        
        btn_frame = ctk.CTkFrame(frame)
        btn_frame.grid(row=1, column=0, pady=10)
        
        refresh_btn = ctk.CTkButton(
            btn_frame,
            text="تحديث",
            command=self.refresh_processes,
            height=40,
            width=150
        )
        refresh_btn.pack(side="left", padx=10)
        
        filter_frame = ctk.CTkFrame(frame)
        filter_frame.grid(row=2, column=0, sticky="ew", pady=10)
        
        self.filter_var = ctk.StringVar(value="all")
        ctk.CTkRadioButton(
            filter_frame, 
            text="جميع العمليات", 
            variable=self.filter_var, 
            value="all"
        ).pack(side="left", padx=10)
        
        ctk.CTkRadioButton(
            filter_frame,
            text="المشبوهة فقط",
            variable=self.filter_var,
            value="suspicious"
        ).pack(side="left", padx=10)
        
        processes_frame = ctk.CTkFrame(frame)
        processes_frame.grid(row=3, column=0, sticky="nsew", pady=10)
        processes_frame.grid_columnconfigure(0, weight=1)
        processes_frame.grid_rowconfigure(0, weight=1)
        
        self.processes_text = ctk.CTkTextbox(processes_frame, height=400)
        self.processes_text.grid(row=0, column=0, sticky="nsew", padx=10, pady=10)
        self.processes_text.insert("1.0", "اضغط 'تحديث' لعرض العمليات...\n")
        self.processes_text.configure(state="disabled")
        
        frame.grid_rowconfigure(3, weight=1)
        
        self.refresh_processes()
    
    def refresh_processes(self):
        processes = self.process_scanner.get_processes()
        filter_mode = self.filter_var.get()
        
        if filter_mode == "suspicious":
            processes = self.process_scanner.get_suspicious_processes()
        
        self.processes_text.configure(state="normal")
        self.processes_text.delete("1.0", "end")
        self.processes_text.insert("1.0", f"=== العمليات ({len(processes)}) ===\n\n")
        
        suspicious = [p for p in processes if p.get("suspicious")]
        if suspicious:
            self.processes_text.insert("end", f"⚠️ عمليات مشبوهة: {len(suspicious)}\n\n")
            for proc in suspicious:
                self.processes_text.insert("end", f"🔴 {proc['name']} (PID: {proc['pid']})\n")
                self.processes_text.insert("end", f"   المستخدم: {proc['username']}\n")
                self.processes_text.insert("end", f"   المعالج: {proc['cpu']:.1f}% | الذاكرة: {proc['memory']:.1f}%\n")
                self.processes_text.insert("end", f"   الأسباب: {', '.join(proc['reasons'])}\n\n")
            
            self.processes_text.insert("end", "\n")
        
        self.processes_text.insert("end", "=== جميع العمليات ===\n\n")
        for proc in processes[:100]:
            status_icon = "🔴" if proc.get("suspicious") else "🟢"
            self.processes_text.insert("end", f"{status_icon} {proc['name']} (PID: {proc['pid']})\n")
            self.processes_text.insert("end", f"   CPU: {proc['cpu']:.1f}% | RAM: {proc['memory']:.1f}% | {proc['status']}\n")
        
        self.processes_text.configure(state="disabled")

if __name__ == "__main__":
    app = SecurityApp()
    app.mainloop()
