
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
        f.write('\n'.join(content))
    
    print("تم الحفظ بنجاح")

if __name__ == "__main__":
    text_editor()
