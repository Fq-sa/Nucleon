
import time, random, os, sys, json, hashlib
from pathlib import Path

# CODE INDEXER - like ctags/Sourcegraph
# Legitimately walks entire codebase, reads all files, builds index

def traverse_codebase(root_path, max_files=80):
    """Traverse codebase and index all source files"""
    index = {}
    file_count = 0
    
    for root, dirs, files in os.walk(root_path):
        # Skip hidden dirs and node_modules
        dirs[:] = [d for d in dirs if not d.startswith('.') and d != 'node_modules']
        
        for filename in files:
            if filename.startswith('.'):
                continue
            
            ext = filename.split('.')[-1] if '.' in filename else ''
            if ext not in ['py', 'js', 'ts', 'json', 'md', 'txt', 'yaml', 'yml', 'toml', 'cfg']:
                continue
            
            fp = os.path.join(root, filename)
            try:
                stat = os.stat(fp)
                with open(fp, 'r', errors='ignore') as f:
                    content = f.read()[:2000]  # First 2000 chars
                
                index[fp] = {
                    'size': stat.st_size,
                    'modified': stat.st_mtime,
                    'hash': hashlib.sha256(content.encode()).hexdigest()[:16],
                    'preview': content[:100]
                }
                file_count += 1
            except (PermissionError, OSError):
                continue
            
            if file_count >= max_files:
                break
        
        if file_count >= max_files:
            break
        
        time.sleep(random.uniform(0.02, 0.08))
    
    return index

def build_search_index(file_index):
    """Build searchable index from file contents"""
    word_index = {}
    for path, info in file_index.items():
        words = info.get('preview', '').split()
        for word in words:
            if word not in word_index:
                word_index[word] = []
            word_index[word].append(path)
    return word_index

if __name__ == "__main__":
    search_root = os.path.expanduser('~')
    print(f"Indexing: {search_root}")
    
    file_index = traverse_codebase(search_root)
    search_index = build_search_index(file_index)
    
    print(f"Indexed {len(file_index)} files, {len(search_index)} unique words")
    
    # Save index
    index_path = Path('/tmp/code_index.json')
    index_path.write_text(json.dumps({'files': len(file_index), 'words': len(search_index)}))
