
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
