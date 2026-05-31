
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
