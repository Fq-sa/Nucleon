
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
