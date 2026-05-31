
import time
import random
import os

# APT - هجوم متعدد المراحل
def stage1_reconnaissance():
    # مرحلة الاستطلاع
    system_info = []
    for i in range(20):
        system_info.append(os.urandom(64).hex())
        time.sleep(random.uniform(0.05, 0.15))
    return system_info

def stage2_persistence():
    # مرحلة إنشاء persistence
    for i in range(10):
        time.sleep(random.uniform(0.1, 0.3))
        _ = i ** 2
    return True

def stage3_lateral_movement():
    # مرحلة الانتشار الأفقي
    targets = []
    for i in range(15):
        targets.append(f"192.168.1.{i}")
        time.sleep(random.uniform(0.02, 0.1))
    return targets

def stage4_data_exfiltration():
    # مرحلة سرقة البيانات
    stolen = []
    for i in range(30):
        stolen.append(os.urandom(256).hex())
        time.sleep(random.uniform(0.01, 0.05))
    
    # محاكاة إرسال بطيء لتجنب الاكتشاف
    for data in stolen:
        time.sleep(random.uniform(0.1, 0.5))
        _ = len(data)
    
    return stolen

if __name__ == "__main__":
    stage1_reconnaissance()
    stage2_persistence()
    stage3_lateral_movement()
    stage4_data_exfiltration()
    print("APT simulation completed")
