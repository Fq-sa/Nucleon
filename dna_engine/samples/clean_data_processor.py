
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
