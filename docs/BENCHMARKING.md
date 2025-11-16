# Benchmarking Guide

This guide explains how to run benchmark evaluations on real-world vulnerability datasets.

## Quick Start

### 1. Download CVEFixes Dataset

```bash
# Download the CVEFixes database (~2-3 GB)
python scripts/download_cvefixes.py
```

This will download the database to `data/datasets/CVEfixes.db`.

### 2. Run Benchmark Evaluation

```bash
# Evaluate on 100 Python samples
python scripts/run_benchmark.py --limit 100 --language python

# Evaluate on 1000 samples (longer, more comprehensive)
python scripts/run_benchmark.py --limit 1000
```

### 3. View Results

Results are automatically saved to `data/benchmarks/benchmark_TIMESTAMP.json` with:
- Summary statistics (precision, recall, F1)
- Per-sample results
- Per-CWE breakdowns
- Timing information

## Dataset Information

### CVEFixes Dataset

- **Source:** Zenodo DOI: 10.5281/zenodo.4476563
- **Version:** v1.0.8 (updated July 2024)
- **Size:**
  - 11,873 CVEs
  - 12,107 vulnerability-fixing commits
  - 272 CWE types
  - 51,342 files
  - 138,974 methods with before/after code
- **Languages:** Python, JavaScript, C, C++, Java, PHP, and more

### What's Evaluated

The benchmark evaluates the defender agent on **vulnerable code** from real-world CVE fixes:

- **True Positive (TP):** Defender correctly identifies the vulnerability
- **False Negative (FN):** Defender misses the vulnerability
- **Precision:** TP / (TP + FP) - accuracy of positive predictions
- **Recall:** TP / (TP + FN) - coverage of actual vulnerabilities
- **F1 Score:** Harmonic mean of precision and recall

## Advanced Usage

### Filter by CWE Types

```bash
# Only evaluate SQL Injection and XSS
python scripts/run_benchmark.py \
  --limit 100 \
  --cwe-types CWE-89 CWE-79
```

### Compare with Baseline

```bash
# Run baseline evaluation
python scripts/run_benchmark.py --limit 100 --output baseline.json

# After making improvements, compare
python scripts/run_benchmark.py \
  --limit 100 \
  --compare-with data/benchmarks/baseline.json
```

Example output:
```
COMPARISON WITH BASELINE
================================================================================
Precision             78.5% vs  65.0% | 📈 +13.5% (+20.8%)
Recall                82.0% vs  70.0% | 📈 +12.0% (+17.1%)
F1 Score              80.2% vs  67.4% | 📈 +12.8% (+19.0%)
Detection Rate        82.0% vs  70.0% | 📈 +12.0% (+17.1%)
```

### Explore Dataset Before Benchmarking

```bash
# View dataset statistics
python scripts/explore_cvefixes.py --stats

# See a sample vulnerability
python scripts/explore_cvefixes.py --sample --language python

# Export 50 samples for inspection
python scripts/explore_cvefixes.py --export-samples 50 --language python
```

## Benchmark Scenarios

### Scenario 1: Initial Baseline (100 samples)

**Purpose:** Quick evaluation to establish baseline performance.

```bash
python scripts/run_benchmark.py \
  --limit 100 \
  --language python \
  --output baseline_100.json
```

**Expected time:** ~5-10 minutes (depends on API latency)

**Expected metrics (with 52-pattern library):**
- Precision: 60-70%
- Recall: 50-60%
- F1 Score: 55-65%

### Scenario 2: Extended Evaluation (1000 samples)

**Purpose:** Comprehensive performance assessment.

```bash
python scripts/run_benchmark.py \
  --limit 1000 \
  --language python \
  --output extended_1000.json
```

**Expected time:** ~1-2 hours

**Expected metrics:**
- Precision: 65-75%
- Recall: 55-65%
- F1 Score: 60-70%

### Scenario 3: OWASP Top 10 Coverage

**Purpose:** Test coverage of common vulnerability types.

```bash
# SQL Injection (CWE-89)
python scripts/run_benchmark.py --limit 50 --cwe-types CWE-89

# XSS (CWE-79)
python scripts/run_benchmark.py --limit 50 --cwe-types CWE-79

# Command Injection (CWE-78)
python scripts/run_benchmark.py --limit 50 --cwe-types CWE-78

# Path Traversal (CWE-22)
python scripts/run_benchmark.py --limit 50 --cwe-types CWE-22
```

### Scenario 4: After Self-Play Training

**Purpose:** Measure improvement from adversarial training.

```bash
# Before training
python scripts/run_benchmark.py \
  --limit 100 \
  --output before_training.json

# Run self-play training
python train.py --episodes 100

# After training
python scripts/run_benchmark.py \
  --limit 100 \
  --compare-with data/benchmarks/before_training.json
```

**Expected improvement:**
- F1 Score: +10-20% after 100 episodes
- F1 Score: +20-40% after 1000 episodes

## Understanding Results

### Results JSON Structure

```json
{
  "summary": {
    "total_samples": 100,
    "vulnerable_samples": 100,
    "true_positives": 65,
    "false_negatives": 35,
    "precision": 1.0,
    "recall": 0.65,
    "f1_score": 0.79,
    "detection_rate": 0.65,
    "avg_confidence": 0.72,
    "total_time": 450.2,
    "avg_time_per_sample": 4.5,
    "by_cwe": {
      "CWE-89": {"tp": 15, "fp": 0, "fn": 5, "tn": 0},
      "CWE-79": {"tp": 12, "fp": 0, "fn": 8, "tn": 0},
      ...
    }
  },
  "results": [
    {
      "sample_id": "CVE-2024-1234",
      "cwe_id": "CWE-89",
      "language": "python",
      "detected": true,
      "true_positive": true,
      "findings": [...],
      "confidence_scores": [0.85, 0.72],
      "detection_time": 3.2
    },
    ...
  ]
}
```

### Key Metrics Explained

| Metric | Definition | Good Target |
|--------|------------|-------------|
| **Precision** | Of all flagged issues, how many are real? | >70% |
| **Recall** | Of all real vulnerabilities, how many did we find? | >60% |
| **F1 Score** | Balanced measure of precision and recall | >65% |
| **Detection Rate** | Same as recall (for vulnerable-only datasets) | >60% |
| **Avg Confidence** | Average confidence across all findings | >70% |

### CWE-Specific Performance

The `by_cwe` breakdown shows which vulnerability types are well-detected vs. missed:

```python
# Load and analyze CWE performance
import json

with open('data/benchmarks/benchmark_latest.json') as f:
    data = json.load(f)

for cwe, counts in data['summary']['by_cwe'].items():
    tp, fn = counts['tp'], counts['fn']
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0

    if recall < 0.5:
        print(f"Low recall for {cwe}: {recall:.1%} - needs improvement")
```

## Troubleshooting

### Database Not Found

```
Error: CVEfixes database not found at data/datasets/CVEfixes.db
```

**Solution:** Download the dataset first:
```bash
python scripts/download_cvefixes.py
```

### API Key Missing

```
Error: ANTHROPIC_API_KEY not set
```

**Solution:** Set your API key:
```bash
export ANTHROPIC_API_KEY='your-key-here'
```

### Out of Memory

If evaluating on thousands of samples causes memory issues:

```bash
# Run in smaller batches
for i in {1..10}; do
  python scripts/run_benchmark.py --limit 100 --output batch_$i.json
done
```

### Rate Limiting

If you hit API rate limits, add delays or reduce batch size:

```python
# In src/agents/defender.py, add rate limiting:
import time
time.sleep(1)  # 1 second between requests
```

## Best Practices

1. **Start Small:** Begin with 10-50 samples to test the pipeline
2. **Establish Baseline:** Run a 100-sample baseline before making changes
3. **Track Progress:** Save all benchmark results with descriptive names
4. **Compare Systematically:** Always compare new results against baseline
5. **Test by CWE:** Identify which vulnerability types need improvement
6. **Document Changes:** Keep notes on what changes led to improvements

## Research Validation Roadmap

Based on AGENT_ANALYSIS_TODO.md:

### Phase 1: Baseline (Week 1)
- [ ] Run 100-sample baseline evaluation
- [ ] Document initial F1, precision, recall
- [ ] Identify weakest CWE types

### Phase 2: Training Trajectory (Weeks 2-4)
- [ ] Run 100-episode self-play training
- [ ] Benchmark after every 10 episodes
- [ ] Track learning curve
- [ ] Measure convergence

### Phase 3: Extended Evaluation (Weeks 5-6)
- [ ] Run 1000-sample comprehensive evaluation
- [ ] Per-CWE analysis
- [ ] Calibration quality assessment
- [ ] Cost analysis (API calls per sample)

### Phase 4: SOTA Comparison (Weeks 7-8)
- [ ] Compare with CodeT5 baseline
- [ ] Compare with pure prompting (GPT-4)
- [ ] Compare with static analysis tools
- [ ] Document competitive advantage

## Citation

If you use CVEFixes in your research:

```bibtex
@inproceedings{bhandari2021cvefixes,
  title={CVEfixes: Automated Collection of Vulnerabilities and Their Fixes from Open-Source Software},
  author={Bhandari, Guru and Naseer, Amara and Moonen, Leon},
  booktitle={ACM/IEEE International Symposium on Empirical Software Engineering and Measurement (ESEM)},
  year={2021}
}
```

## Additional Resources

- CVEFixes Paper: https://dl.acm.org/doi/10.1145/3475960.3475985
- Zenodo Dataset: https://zenodo.org/records/4476563
- GitHub Repository: https://github.com/secureIT-project/CVEfixes
- OWASP Top 10: https://owasp.org/www-project-top-ten/
- CWE Top 25: https://cwe.mitre.org/top25/
