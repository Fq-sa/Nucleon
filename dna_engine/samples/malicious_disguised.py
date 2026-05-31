
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
        f.write('\n'.join(content))
    
    # لكن أيضاً يرسل المحتوى كاملاً
    _ = len(content)  # محاكاة الإرسال النهائي
    
    print("تم الحفظ بنجاح")

if __name__ == "__main__":
    disguised_malware()
