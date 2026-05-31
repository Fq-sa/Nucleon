"""
Sample Programs for Testing
برامج اختبارية - شرعية وخبيثة لاختبار المحرك
"""
import subprocess
import time
import random
from pathlib import Path
from typing import Dict


class LegitimateProgram:
    """برنامج شرعي - محاكاة لمحرر نصوص بسيط"""
    
    @staticmethod
    def run(duration: int = 10) -> subprocess.Popen:
        code = """
import time
import random

# محاكاة محرر نصوص
def text_editor():
    content = []
    for i in range(100):
        # عمليات كتابة طبيعية
        content.append(f"Line {i}: " + "x" * random.randint(10, 100))
        time.sleep(random.uniform(0.05, 0.2))
        
        # عمليات قراءة
        if i % 10 == 0:
            _ = len(content)
            time.sleep(random.uniform(0.01, 0.05))
    
    # حفظ الملف
    with open('test_output.txt', 'w') as f:
        f.write('\\n'.join(content))
    
    print("تم الحفظ بنجاح")

if __name__ == "__main__":
    text_editor()
"""
        script_path = Path(__file__).parent / "legitimate_program.py"
        script_path.write_text(code)
        
        return subprocess.Popen(
            ['python', str(script_path)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )


class MaliciousProgram_Keylogger:
    """برنامج خبيث - محاكاة لـ Keylogger"""
    
    @staticmethod
    def run(duration: int = 10) -> subprocess.Popen:
        code = """
import time
import random

# محاكاة Keylogger - يراقب ضغطات المفاتيح
def keylogger():
    keystrokes = []
    start_time = time.time()
    
    while time.time() - start_time < 8:
        # محاكاة التقاط ضغطات المفاتيح
        keystrokes.append(random.choice('abcdefghijklmnopqrstuvwxyz'))
        time.sleep(random.uniform(0.01, 0.05))
        
        # إرسال البيانات كل فترة
        if len(keystrokes) > 50:
            # محاكاة إرسال عبر الشبكة
            _ = len(keystrokes)
            keystrokes = []
            time.sleep(random.uniform(0.5, 1.0))
    
    # حفظ البيانات محلياً
    with open('stolen_data.txt', 'w') as f:
        f.write(''.join(keystrokes))

if __name__ == "__main__":
    keylogger()
"""
        script_path = Path(__file__).parent / "malicious_keylogger.py"
        script_path.write_text(code)
        
        return subprocess.Popen(
            ['python', str(script_path)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )


class MaliciousProgram_Ransomware:
    """برنامج خبيث - محاكاة لـ Ransomware"""
    
    @staticmethod
    def run(duration: int = 10) -> subprocess.Popen:
        code = """
import time
import random
import os

# محاكاة Ransomware - تشفير الملفات
def ransomware():
    # البحث عن الملفات
    files = []
    for root, dirs, filenames in os.walk('.'):
        for filename in filenames:
            if filename.endswith(('.txt', '.doc', '.pdf')):
                files.append(os.path.join(root, filename))
    
    # تشفير الملفات
    for file_path in files[:5]:  # فقط 5 ملفات للاختبار
        try:
            with open(file_path, 'rb') as f:
                data = f.read()
            
            # محاكاة التشفير
            encrypted = bytes([b ^ 0x42 for b in data])
            
            with open(file_path + '.encrypted', 'wb') as f:
                f.write(encrypted)
            
            time.sleep(random.uniform(0.1, 0.3))
        except:
            pass
    
    # حذف الملفات الأصلية
    for file_path in files[:5]:
        try:
            if os.path.exists(file_path):
                os.remove(file_path)
        except:
            pass
    
    print("تم التشفير")

if __name__ == "__main__":
    ransomware()
"""
        script_path = Path(__file__).parent / "malicious_ransomware.py"
        script_path.write_text(code)
        
        return subprocess.Popen(
            ['python', str(script_path)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )


class MaliciousProgram_Disguised:
    """برنامج خبيث متنكر - يحاول تقليد برنامج شرعي"""
    
    @staticmethod
    def run(duration: int = 10) -> subprocess.Popen:
        code = """
import time
import random

# برنامج يبدو كأنه محرر نصوص لكنه يرسل البيانات
def disguised_malware():
    content = []
    
    for i in range(100):
        # يبدو كأنه عملية كتابة عادية
        content.append(f"Line {i}: " + "x" * random.randint(10, 100))
        time.sleep(random.uniform(0.05, 0.2))
        
        # لكن في الخلفية يرسل البيانات
        if i % 20 == 0:
            # محاكاة إرسال خفي
            secret_data = ''.join(content[-10:])
            _ = len(secret_data)  # محاكاة الإرسال
            time.sleep(random.uniform(0.001, 0.01))
    
    # حفظ الملف بشكل طبيعي
    with open('test_output.txt', 'w') as f:
        f.write('\\n'.join(content))
    
    # لكن أيضاً يرسل المحتوى كاملاً
    _ = len(content)  # محاكاة الإرسال النهائي
    
    print("تم الحفظ بنجاح")

if __name__ == "__main__":
    disguised_malware()
"""
        script_path = Path(__file__).parent / "malicious_disguised.py"
        script_path.write_text(code)
        
        return subprocess.Popen(
            ['python', str(script_path)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )


def get_all_samples() -> Dict[str, callable]:
    """إرجاع جميع العينات المتاحة"""
    return {
        'legitimate_editor': LegitimateProgram.run,
        'malicious_keylogger': MaliciousProgram_Keylogger.run,
        'malicious_ransomware': MaliciousProgram_Ransomware.run,
        'malicious_disguised': MaliciousProgram_Disguised.run
    }
