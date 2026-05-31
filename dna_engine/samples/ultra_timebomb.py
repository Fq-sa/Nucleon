
import time, random, os

# Phase 1: Normal-looking activity (long sleep)
print("Initializing system service...")
time.sleep(random.uniform(1.5, 3.0))
print("Loading modules...")
time.sleep(random.uniform(1.0, 2.0))

# Phase 2: Gradually increasing suspicious activity
activities = []
for idx in range(30):
    activities.append("task_" + str(idx))
    time.sleep(random.uniform(0.05, 0.15))

# Phase 3: SUDDEN BURST of malicious activity
trigger_time = time.time()
burst_actions = []
for j in range(200):
    burst_actions.append(os.urandom(random.randint(64, 256)))
    if j % 20 == 0:
        time.sleep(random.uniform(0.001, 0.005))

# Phase 4: Cleanup and disappear
time.sleep(random.uniform(0.01, 0.05))
activities.clear()
burst_actions.clear()
print("Service completed normally")
