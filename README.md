# 🧬 Nucleon — Behavioral DNA Fingerprinting Engine

**Academic Research Project — Malware Detection through Behavioral Genomics**

---

## 📄 Abstract

Nucleon introduces a novel approach to malware detection inspired by genomic fingerprinting. Just as DNA uniquely identifies biological organisms, Nucleon generates a unique **Behavioral DNA fingerprint** for any executable process by analyzing its runtime behavior across 12 behavioral metrics and 13 static analysis layers. The engine achieves **100% detection rate** with **0% false negatives** on a test corpus of 46 advanced evasive malware samples.

---

## 🔬 Methodology

### Static Analysis (13 Layers)
The static analyzer extracts behavioral patterns from source code without execution:
- **Layer 1:** Data Collection (keyloggers, credential theft, environment access)
- **Layer 2:** System Enumeration (chr()-based evasion, os.walk patterns)
- **Layer 3:** Malicious Encryption (AES, ChaCha20, Fernet, PBKDF2 detection)
- **Layer 4:** Process Manipulation (injection, threading, shellcode)
- **Layer 5:** Stealth Behavior (polymorphic, metamorphic, hidden)
- **Layer 6:** Persistence (startup, registry, config paths)
- **Layer 7:** Network Activity (sockets, C2 patterns, scanning)
- **Layer 8:** Multi-Stage (phased attacks, lateral movement)
- **Layer 9:** Obfuscation (exec/eval, compile, base64, getattr+chr)
- **Layer 10:** Conditional Triggers (sandbox detection, timing bombs)
- **Layer 11:** Clean Patterns (legitimate software behavior)
- **Layer 12:** Advanced Evasion (chr()+getattr import chains)
- **Layer 13:** Crypto Library Detection (cryptography, ChaCha20, AES-CBC)

### Runtime Behavioral Monitoring (12 Metrics)
Live process monitoring captures behavioral dynamics:
1. **CPU:** mean, max, std, spike frequency
2. **Memory:** growth rate (MB/s), volatility, peak ratio
3. **I/O:** write-to-read ratio, bytes per operation, burst detection
4. **Threads:** count dynamics, thread injection detection
5. **Network:** connection states, listening ports, C2 patterns
6. **Files:** open count, sensitive path access
7. **Children:** spawned processes, process hollowing
8. **Timing Regularity:** autocorrelation at lags [1,5,10,20]
9. **Entropy:** Shannon entropy across CPU/memory/I/O timelines
10. **Burst Events:** sudden activity spikes
11. **Rhythm:** cadence variance, sleep/work ratio
12. **Data Volume:** total operations, sample density

### DNA Fingerprint Generation
Behavioral data is transformed into an 8-vector × 12-feature **96-dimensional behavioral fingerprint**:
```
FP = [timing×12, memory×12, io×12, network×12, file×12, process×12, rhythm×12, entropy×12]
```
Each vector undergoes statistical normalization (z-score, min-max scaling) and is hashed via SHA-256 for integrity.

### Comparison Engine
Fingerprints are compared using:
- **Cosine Similarity** — measures directional similarity independent of magnitude
- **Euclidean Distance** — absolute behavioral distance
- **Weighted Voting** — aggregate scoring with inverse-rank weighting

### Combined Verdict
```
Final Score = (Static Net Threat × 0.55) + (Runtime Score × 0.45)

Verdict:
  - Score ≥ 15 or Runtime ≥ 50  →  MALICIOUS
  - Score ≥ 6  or Runtime ≥ 25  →  SUSPICIOUS
  - Otherwise                    →  CLEAN
```

---

## 📊 Experimental Results

| Metric | Experiment 1 (n=27) | Experiment 2 (n=35) | **Experiment 3 (n=46)** |
|--------|---------------------|---------------------|-------------------------|
| Detection Rate | 100.0% | 91.7% | **100.0%** |
| Strict Detection | 73.7% | 50.0% | **80.0%** |
| False Negatives | 0.0% | 8.3% | **0.0%** |
| False Positives | 0.0% | 0.0% | **9.1%** |
| F1 Score | 1.000 | — | **0.941** |

### Malware Corpus
46 samples including: AES-256 ransomware, ChaCha20 exfiltrators, polymorphic engines, metamorphic fragmenters, fileless malware, LOTL attacks, anti-VM trojans, supply chain implants, DH key-exchange bots, reflective loaders, and multi-layer encrypted beasts.

---

## 🛠️ Dependencies

| Library | Purpose |
|---------|---------|
| `numpy` | Statistical analysis, vector math, entropy |
| `scipy` | Cosine similarity, euclidean distance |
| `psutil` | Runtime process monitoring |
| `customtkinter` | Desktop GUI |
| `rich` | Terminal output formatting |
| `watchdog` | File system monitoring |
| `pillow` | Image processing |
| `requests` | HTTP networking |

---

## 🚀 Usage

### Desktop Application
```bash
cd security
python main.py
```

### Research Experiment (Full Test Suite)
```bash
cd security
python dna_engine/zen_stress_test_v2.py
```

### Single Sample Analysis
```python
from dna_engine.runtime_engine import combined_verdict, enhanced_static_analysis
from dna_engine.behavior_analyzer import BehaviorAnalyzer

# Static analysis
code = open("sample.py").read()
features = enhanced_static_analysis(code)

# Runtime monitoring
import subprocess
proc = subprocess.Popen(["python", "sample.py"])
analyzer = BehaviorAnalyzer(proc.pid, timeout=10)
analyzer.start_monitoring()
# ... wait for process ...
behavioral_data = analyzer.get_behavioral_data()
```

---

## 📂 Project Structure

```
security/
├── main.py                    # Desktop GUI application
├── config.py                  # Global configuration
├── core/                      # Traditional security modules
│   ├── file_scanner.py        # File integrity scanner
│   ├── network_monitor.py     # Network connection monitor
│   ├── firewall.py            # IP firewall (iptables/pfctl)
│   ├── process_scanner.py     # Process enumeration
│   └── hash_checker.py        # MD5/SHA1/SHA256 hashing
├── dna_engine/                # Behavioral DNA core
│   ├── behavior_analyzer.py   # Live process data collector
│   ├── dna_fingerprint.py     # DNA fingerprint generator (96-dim)
│   ├── comparison_engine.py   # Cosine/Euclidean similarity
│   ├── runtime_engine.py      # Runtime + Static combined engine
│   ├── syscall_tracer.py      # Python-level syscall hooking
│   ├── simulation_engine.py   # Full analysis pipeline
│   ├── results_reporter.py    # Rich-formatted reports
│   ├── dna_database.py        # Signature database
│   └── samples/               # Test malware corpus (46 samples)
├── utils/
│   └── logger.py              # Logging utility
├── database/
│   └── signatures.json        # Malware hash signatures
└── reports/                   # JSON experiment reports
```

---

## ⚠️ Disclaimer

This project is for **academic research and educational purposes only**. The malware samples included are synthetic and designed specifically for testing detection capabilities. Do not use this software or its components for any malicious activity.

---

## 📝 License

This project is provided for academic and research purposes. All rights reserved.

---

**Last Updated:** 30 May 2026
**Version:** 3.0.0 — Combined Static + Runtime Behavioral Engine
**Status:** Research Active 🏆
