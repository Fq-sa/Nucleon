"""توليد بيانات تدريب من العينات وتدريب XGBoost"""
import json
import re
from pathlib import Path

# Read the report
report_path = Path(__file__).parent / "reports" / "nucleon_v5_report.json"
with open(report_path) as f:
    report = json.load(f)

# Auto-label samples based on filename heuristics
training_samples = []

MALWARE_INDICATORS = [
    'zen', 'mal', 'trojan', 'ransom', 'keylog', 'steal',
    'inject', 'backdoor', 'worm', 'bot', 'rootkit',
    'loader', 'dropper', 'crypt', 'obfuscat', 'hollow',
    'reflective', 'meterpreter', 'apt', 'beast',
    'locker', 'exfil', 'antivm', 'marshal', 'poly',
    'ghost', 'caller', 'timebomb', 'supplychain',
    'rot13', 'xor', 'memmap', 'chacha', 'fernet',
    'aes', 'disguised', 'hollower', 'dh_bot',
    'hybrid', 'fragmented', 'silent', 'stealth',
    'phantom', 'encoder',
]

CLEAN_INDICATORS = [
    'clean', 'legitimate', 'webserver', 'devops',
    'backup', 'indexer', 'monitor', 'processor',
    'migrator', 'scanner', 'editor',
]

for sample in report['samples']:
    name = sample['name'].lower()
    
    # Determine label
    if any(x in name for x in CLEAN_INDICATORS):
        label = 0  # clean
    elif any(x in name for x in MALWARE_INDICATORS):
        label = 1  # malware
    else:
        # Unknown - skip or use score heuristic
        if sample['combined_score'] > 25:
            label = 1
        elif sample['combined_score'] < 5:
            label = 0
        else:
            label = -1  # uncertain - skip
    
    if label != -1:
        scores = sample['scores']
        # Ensure all keys exist
        training_samples.append({
            'name': sample['name'],
            'label': label,
            'scores': {
                'ast_score': scores.get('ast', 0),
                'yara_score': scores.get('yara', 0),
                'runtime_score': scores.get('runtime', 0),
                'sandbox_score': scores.get('sandbox', 0),
                'pcap_score': scores.get('pcap', 0),
                'memory_score': scores.get('memory', 0),
                'binary_score': scores.get('binary', 0),
            },
        })

# Save training data
training_data_path = Path(__file__).parent / "reports" / "training_data.json"
with open(training_data_path, 'w') as f:
    json.dump({'samples': training_samples}, f, indent=2)

mal_count = sum(1 for s in training_samples if s['label'] == 1)
clean_count = sum(1 for s in training_samples if s['label'] == 0)

print(f"Training data: {len(training_samples)} samples ({mal_count} malware, {clean_count} clean)")
print(f"Saved to: {training_data_path}")

# Train XGBoost
from xgboost_classifier import get_classifier

classifier = get_classifier()
result = classifier.train_from_file(training_data_path)
print(f"\nTraining result: {json.dumps(result, indent=2, ensure_ascii=False)}")

# Save model
model_path = Path(__file__).parent / "reports" / "xgboost_ensemble_model.json"
classifier.save_model(model_path)
print(f"\nModel saved: {model_path}")
