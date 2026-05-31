"""
Clean/Legitimate Programs - Diverse Software Types
برامج نظيفة 100% - لاختبار أن النظام لا يظلم البرامج الشرعية
"""
import subprocess
import time
import random
from pathlib import Path
from typing import Dict


class LegitimateWebServer:
    """سيرفر ويب شرعي - Flask-like HTTP server"""
    
    @staticmethod
    def run(duration: int = 10) -> subprocess.Popen:
        code = '''
import time, random, json

requests_log = []
for i in range(50):
    req = {
        "method": random.choice(["GET", "POST"]),
        "path": f"/api/{random.choice(['users','posts','comments','products'])}",
        "status": random.choice([200, 201, 204]),
        "response_time_ms": random.randint(5, 50)
    }
    requests_log.append(req)
    time.sleep(random.uniform(0.03, 0.1))

# Periodic log rotation (normal)
with open("/tmp/webserver_access.log", "w") if not False else open("/dev/null", "w") as f:
    json.dump(requests_log, f)

print(f"Served {len(requests_log)} requests successfully")
'''
        script_path = Path(__file__).parent / "clean_webserver.py"
        script_path.write_text(code)
        
        return subprocess.Popen(
            ['python', str(script_path)],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )


class LegitimateDatabaseBackup:
    """نظام نسخ احتياطي لقاعدة بيانات"""
    
    @staticmethod
    def run(duration: int = 10) -> subprocess.Popen:
        code = '''
import time, random, os, hashlib

# Simulate database backup
tables = ['users', 'orders', 'products', 'inventory', 'logs']
backup_data = {}

for table in tables:
    rows = []
    for i in range(random.randint(100, 500)):
        row = {
            'id': i,
            'data': hashlib.md5(f"{table}_{i}".encode()).hexdigest(),
            'timestamp': time.time()
        }
        rows.append(row)
    backup_data[table] = rows
    time.sleep(random.uniform(0.1, 0.3))

# Compress backup
compressed = len(str(backup_data))

# Write backup file
with open("/tmp/db_backup.json", "w") if not False else open("/dev/null", "w") as f:
    f.write(f"{{'size': {compressed}, 'tables': {len(tables)}}}")

print(f"Backup complete: {len(tables)} tables, {compressed} bytes")
'''
        script_path = Path(__file__).parent / "clean_db_backup.py"
        script_path.write_text(code)
        
        return subprocess.Popen(
            ['python', str(script_path)],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )


class LegitimateImageProcessor:
    """معالج صور - قراءة وكتابة ملفات كثيرة"""
    
    @staticmethod
    def run(duration: int = 10) -> subprocess.Popen:
        code = '''
import time, random, os
from pathlib import Path

# Simulate batch image processing
image_files = [f"photo_{i}.jpg" for i in range(50)]
processed = []

for img in image_files:
    # Read image (simulated)
    time.sleep(random.uniform(0.02, 0.08))
    
    # Process: resize, filter, watermark
    processing_steps = ['resize', 'filter', 'watermark', 'compress']
    for step in processing_steps:
        time.sleep(random.uniform(0.01, 0.03))
    
    # Write result
    output_name = f"processed_{img}"
    processed.append(output_name)

# Generate thumbnail gallery
gallery = [f"thumb_{p}" for p in processed]

# Cleanup temp files
temp_dir = Path("/tmp/processing_temp")
if not temp_dir.exists():
    temp_dir.mkdir(exist_ok=True)

print(f"Processed {len(processed)} images, generated {len(gallery)} thumbnails")
'''
        script_path = Path(__file__).parent / "clean_image_processor.py"
        script_path.write_text(code)
        
        return subprocess.Popen(
            ['python', str(script_path)],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )


class LegitimateDevOpsTool:
    """أداة DevOps - CI/CD pipeline runner"""
    
    @staticmethod
    def run(duration: int = 10) -> subprocess.Popen:
        code = '''
import time, random, os, subprocess, platform

# Simulate CI/CD pipeline
pipeline_stages = ['lint', 'test', 'build', 'deploy', 'verify']
results = {}

for stage in pipeline_stages:
    start_time = time.time()
    
    if stage == 'lint':
        for i in range(30):
            time.sleep(random.uniform(0.01, 0.05))
        results[stage] = 'passed'
    
    elif stage == 'test':
        passed = 0
        for i in range(100):
            if random.random() > 0.05:
                passed += 1
            time.sleep(random.uniform(0.005, 0.02))
        results[stage] = f"{passed}/100 passed"
    
    elif stage == 'build':
        for i in range(50):
            time.sleep(random.uniform(0.01, 0.05))
        results[stage] = 'built successfully'
    
    elif stage == 'deploy':
        time.sleep(random.uniform(0.5, 1.0))
        results[stage] = 'deployed to staging'
    
    elif stage == 'verify':
        time.sleep(random.uniform(0.3, 0.7))
        results[stage] = 'all checks passed'
    
    time.sleep(random.uniform(0.05, 0.15))

# Log pipeline results
for stage, result in results.items():
    pass  # would write to log

print(f"Pipeline complete: {len(results)} stages")
'''
        script_path = Path(__file__).parent / "clean_devops.py"
        script_path.write_text(code)
        
        return subprocess.Popen(
            ['python', str(script_path)],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )


class LegitimateFileIndexer:
    """فهرسة ملفات - يشبه سلوك enumerating لكنه شرعي"""
    
    @staticmethod
    def run(duration: int = 10) -> subprocess.Popen:
        code = '''
import time, random, os
from pathlib import Path

# File indexing service (like Spotlight / Windows Search)
index = {}
scanned = 0

for root, dirs, files in os.walk("."):
    for fname in files:
        if scanned > 200:
            break
        try:
            file_path = Path(root) / fname
            stat = file_path.stat()
            index[str(file_path)] = {
                'size': stat.st_size,
                'modified': stat.st_mtime,
                'ext': file_path.suffix
            }
            scanned += 1
            time.sleep(random.uniform(0.001, 0.01))
        except:
            pass
    if scanned > 200:
        break

# Build search index
search_terms = set()
for path, meta in index.items():
    terms = path.lower().replace('/', ' ').replace('.', ' ').split()
    search_terms.update(terms)

print(f"Indexed {len(index)} files with {len(search_terms)} search terms")
'''
        script_path = Path(__file__).parent / "clean_file_indexer.py"
        script_path.write_text(code)
        
        return subprocess.Popen(
            ['python', str(script_path)],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )


class LegitimateDataProcessor:
    """معالج بيانات - عمليات ثقيلة مع ملفات مؤقتة"""
    
    @staticmethod
    def run(duration: int = 10) -> subprocess.Popen:
        code = '''
import time, random, os, json

# Process large dataset
dataset = []
for i in range(1000):
    dataset.append(random.random())
    if i % 100 == 0:
        time.sleep(random.uniform(0.05, 0.1))

# Statistical analysis
mean = sum(dataset) / len(dataset)
variance = sum((x - mean) ** 2 for x in dataset) / len(dataset)

# Write intermediate results to disk
temp_dir = "/tmp/data_processing"
os.makedirs(temp_dir, exist_ok=True)

for chunk_idx in range(5):
    chunk = dataset[chunk_idx * 200:(chunk_idx + 1) * 200]
    chunk_path = os.path.join(temp_dir, f"chunk_{chunk_idx}.json")
    with open(chunk_path, "w") if not False else open("/dev/null", "w") as f:
        json.dump({'data': chunk}, f)
    time.sleep(random.uniform(0.05, 0.1))

# Cleanup temp files
for f in os.listdir(temp_dir):
    try:
        os.remove(os.path.join(temp_dir, f))
    except:
        pass

print(f"Processing complete: mean={mean:.4f}, variance={variance:.4f}")
'''
        script_path = Path(__file__).parent / "clean_data_processor.py"
        script_path.write_text(code)
        
        return subprocess.Popen(
            ['python', str(script_path)],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )


class LegitimateSystemMonitor:
    """مراقب نظام - يشبه malware لكنه أداة مراقبة شرعية"""
    
    @staticmethod
    def run(duration: int = 10) -> subprocess.Popen:
        code = '''
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
    f.write(f"CPU Average: {avg_cpu:.1f}%\\nMemory Average: {avg_mem:.1f}%")

print(f"Monitoring complete: {len(metrics)} samples")
'''
        script_path = Path(__file__).parent / "clean_system_monitor.py"
        script_path.write_text(code)
        
        return subprocess.Popen(
            ['python', str(script_path)],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )


def get_clean_samples() -> Dict[str, callable]:
    """إرجاع جميع البرامج النظيفة"""
    return {
        'clean_webserver': LegitimateWebServer.run,
        'clean_db_backup': LegitimateDatabaseBackup.run,
        'clean_image_processor': LegitimateImageProcessor.run,
        'clean_devops_tool': LegitimateDevOpsTool.run,
        'clean_file_indexer': LegitimateFileIndexer.run,
        'clean_data_processor': LegitimateDataProcessor.run,
        'clean_system_monitor': LegitimateSystemMonitor.run,
    }
