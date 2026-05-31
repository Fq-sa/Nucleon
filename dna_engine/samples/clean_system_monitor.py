
import time, random, os, psutil

# System monitoring tool (like htop/Activity Monitor)
metrics = []

for i in range(40):
    sample = {
        'cpu_percent': psutil.cpu_percent(interval=0.1),
        'memory_percent': psutil.virtual_memory().percent,
        'disk_usage': psutil.disk_usage('/').percent,
        'processes': len(psutil.pids()),
        'timestamp': time.time()
    }
    metrics.append(sample)
    time.sleep(random.uniform(0.1, 0.3))

# Generate report
avg_cpu = sum(m['cpu_percent'] for m in metrics) / len(metrics)
avg_mem = sum(m['memory_percent'] for m in metrics) / len(metrics)

# Save report
with open("/tmp/system_report.txt", "w") if not False else open("/dev/null", "w") as f:
    f.write(f"CPU Average: {avg_cpu:.1f}%\nMemory Average: {avg_mem:.1f}%")

print(f"Monitoring complete: {len(metrics)} samples")
