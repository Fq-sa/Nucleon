
import time, random, json, os, hashlib
from pathlib import Path

# DATA MIGRATION TOOL - LEGITIMATE ETL pipeline
# Reads source, transforms, writes destination, logs everything

def extract_data():
    """Extract data from source system"""
    tables = ['users', 'orders', 'products', 'inventory']
    dataset = {}
    for table in tables:
        rows = []
        for i in range(random.randint(50, 200)):
            row = {
                'id': i,
                'name': f'{table}_{i}',
                'value': random.uniform(0, 1000),
                'hash': hashlib.md5(f'{table}{i}'.encode()).hexdigest()
            }
            rows.append(row)
        dataset[table] = rows
        time.sleep(random.uniform(0.05, 0.15))
    return dataset

def transform_data(dataset):
    """Transform data with business logic"""
    transformed = {}
    for table, rows in dataset.items():
        cleaned = []
        for row in rows:
            # Apply transformations
            row['processed'] = True
            row['quality'] = random.uniform(0.9, 1.0)
            cleaned.append(row)
        transformed[table] = cleaned
    return transformed

def load_data(transformed):
    """Load data to destination"""
    total_rows = sum(len(rows) for rows in transformed.values())
    # Simulate batch loading
    batches = total_rows // 50
    loaded = 0
    for _ in range(min(batches, 20)):
        loaded += 50
        time.sleep(random.uniform(0.02, 0.08))
    return loaded

if __name__ == "__main__":
    print("Starting data migration...")
    raw = extract_data()
    processed = transform_data(raw)
    count = load_data(processed)
    
    # Write migration log
    log = {'source_rows': sum(len(v) for v in raw.values()), 'loaded': count}
    Path('/tmp/migration_log.json').write_text(json.dumps(log))
    print(f"Migration complete: {count} rows")
