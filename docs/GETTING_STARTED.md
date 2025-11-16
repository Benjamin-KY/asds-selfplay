# Getting Started with ASDS Self-Play

This guide will walk you through setting up and running the ASDS Self-Play system for vulnerability detection research.

## Table of Contents

1. [System Requirements](#system-requirements)
2. [Installation](#installation)
3. [Quick Start](#quick-start)
4. [Understanding the System](#understanding-the-system)
5. [Running Your First Benchmark](#running-your-first-benchmark)
6. [Running Self-Play Training](#running-self-play-training)
7. [Advanced Usage](#advanced-usage)
8. [Troubleshooting](#troubleshooting)

## System Requirements

**Minimum:**
- Python 3.10 or higher
- 8 GB RAM
- 10 GB disk space
- Claude API key (Anthropic)

**Recommended:**
- Python 3.11+
- 16 GB RAM
- 50 GB disk space (for CVEFixes dataset)
- GPU (optional, for faster processing)

## Installation

### 1. Clone the Repository

```bash
git clone https://github.com/yourusername/asds-selfplay.git
cd asds-selfplay
```

### 2. Install Dependencies

```bash
# Create virtual environment (recommended)
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install requirements
pip install -r requirements.txt
```

### 3. Set Up API Key

```bash
# Set your Anthropic API key
export ANTHROPIC_API_KEY="your-key-here"

# Or add to your shell profile for persistence
echo 'export ANTHROPIC_API_KEY="your-key-here"' >> ~/.bashrc
```

### 4. Verify Installation

```bash
# Run basic tests
python -m pytest tests/test_knowledge_graph.py -v

# Should show passing tests
```

## Quick Start

### Option 1: Run on Built-in Examples (No Dataset Needed)

Perfect for first-time users to understand the system:

```bash
# Run 10 training episodes on built-in vulnerable code examples
python train.py --episodes 10 --dataset vulnerable

# View results in data/episodes/
```

**What this does:**
- Initializes knowledge graph with 52 vulnerability patterns
- Runs defender on 24 vulnerable code samples
- Attacker validates findings
- Updates pattern effectiveness based on results
- Shows learning progress

**Expected output:**
```
================================================================================
ASDS Self-Play Training
================================================================================
Episodes: 10
Dataset: vulnerable
RL Enabled: True

Initializing components...
Loaded 52 vulnerability patterns into knowledge graph
✓ Defender agent ready

Training on: SQL Injection - String Concatenation
  Reward: 15.0 | TP: 1 | FP: 0 | FN: 0

...

TRAINING COMPLETE
================================================================================
Episodes completed: 10
Early average reward: 12.5
Recent average reward: 18.3
Improvement: 5.8 (46.4%)
```

### Option 2: Benchmark on Real Vulnerabilities

Requires downloading CVEFixes dataset (~2-3 GB):

```bash
# Download CVEFixes dataset (one-time setup)
python scripts/download_cvefixes.py

# Run benchmark on 100 real CVEs
python scripts/run_benchmark.py --limit 100 --language python

# View results in data/benchmarks/
```

**Expected metrics (initial baseline):**
- Precision: 60-70%
- Recall: 50-60%
- F1 Score: 55-65%

## Understanding the System

### Core Concepts

**1. Knowledge Graph**
- Stores 52+ vulnerability patterns (SQL injection, XSS, etc.)
- Tracks effectiveness metrics (precision, recall, F1)
- Updates based on attacker feedback
- Located: `data/patterns/knowledge.db`

**2. Defender Agent**
- Analyzes code using LLM + pattern library
- Generates vulnerability findings
- Suggests fixes
- Improves via in-context learning

**3. Attacker Agent**
- Validates defender findings
- Attempts to exploit vulnerabilities
- Provides ground truth feedback
- Tests both vulnerable and fixed code

**4. Self-Play Loop**
```
Defender finds vulnerabilities → Suggests fixes
                ↓
Attacker validates → Provides feedback
                ↓
Knowledge graph updates → Patterns improve
                ↓
Next episode uses better patterns
```

### Directory Structure

```
asds-selfplay/
├── src/
│   ├── agents/          # Defender and attacker agents
│   ├── core/            # Self-play training loop
│   ├── knowledge/       # Knowledge graph
│   ├── patterns/        # 52-pattern vulnerability library
│   ├── datasets/        # CVEFixes loader
│   ├── evaluation/      # Benchmark framework
│   ├── rl/              # Reinforcement learning (GRPO)
│   └── utils/           # Config, logging, audit
├── tests/               # 92 passing tests
├── examples/            # 24 vulnerable code samples
├── scripts/             # CLI tools
├── data/
│   ├── episodes/        # Training episode history
│   ├── patterns/        # Knowledge graph database
│   ├── benchmarks/      # Evaluation results
│   └── datasets/        # CVEFixes database
└── docs/                # Documentation
```

## Running Your First Benchmark

### Step 1: Download CVEFixes

```bash
python scripts/download_cvefixes.py
```

This downloads a ~2-3 GB SQLite database containing:
- 11,873 real CVEs from production software
- 272 CWE types
- 138,974 vulnerable methods with fixes

### Step 2: Explore the Dataset

```bash
# View statistics
python scripts/explore_cvefixes.py --stats

# See a sample vulnerability
python scripts/explore_cvefixes.py --sample --language python

# Export 50 samples for inspection
python scripts/explore_cvefixes.py --export-samples 50 --language python
```

### Step 3: Run Baseline Evaluation

```bash
# Evaluate on 100 Python vulnerabilities
python scripts/run_benchmark.py \
  --limit 100 \
  --language python \
  --output baseline_100.json
```

**Time:** ~5-10 minutes (depends on API latency)

### Step 4: Analyze Results

```bash
# Results are saved to data/benchmarks/baseline_100.json
cat data/benchmarks/baseline_100.json
```

**JSON structure:**
```json
{
  "summary": {
    "total_samples": 100,
    "true_positives": 65,
    "false_negatives": 35,
    "precision": 1.0,
    "recall": 0.65,
    "f1_score": 0.79,
    "by_cwe": {
      "CWE-89": {"tp": 15, "fn": 5},
      "CWE-79": {"tp": 12, "fn": 8},
      ...
    }
  },
  "results": [...]
}
```

## Running Self-Play Training

### Basic Training

```bash
# Train on built-in examples (24 samples)
python train.py --episodes 100 --dataset vulnerable
```

### Advanced Training with CVEFixes

```bash
# First, export CVEFixes samples to examples format
python scripts/explore_cvefixes.py \
  --export-samples 100 \
  --language python

# Then train on them
python train.py --episodes 100 --dataset all
```

### Monitor Training Progress

The system automatically tracks:
- Episode rewards (printed during training)
- True positives, false positives, false negatives
- Pattern effectiveness changes
- Knowledge graph updates

**Example output:**
```
Episode 1:  Reward:  8.5 | TP: 3 | FP: 2 | FN: 5
Episode 10: Reward: 12.3 | TP: 5 | FP: 1 | FN: 3
Episode 50: Reward: 18.7 | TP: 7 | FP: 0 | FN: 2
Episode 100: Reward: 22.1 | TP: 8 | FP: 0 | FN: 1

Improvement: +13.6 points (+160%)
```

### Compare Before/After Training

```bash
# Before training
python scripts/run_benchmark.py --limit 100 --output before.json

# Train
python train.py --episodes 100

# After training
python scripts/run_benchmark.py \
  --limit 100 \
  --compare-with data/benchmarks/before.json
```

**Expected improvement:**
```
COMPARISON WITH BASELINE
Precision       78.5% vs  65.0% | 📈 +13.5% (+20.8%)
Recall          82.0% vs  70.0% | 📈 +12.0% (+17.1%)
F1 Score        80.2% vs  67.4% | 📈 +12.8% (+19.0%)
```

## Advanced Usage

### Filter by Vulnerability Type

```bash
# Only SQL injection vulnerabilities
python scripts/run_benchmark.py \
  --cwe-types CWE-89 \
  --limit 50

# Multiple types
python scripts/run_benchmark.py \
  --cwe-types CWE-89 CWE-79 CWE-78 \
  --limit 100
```

### Custom Configuration

Edit `config.yaml` to customize:

```yaml
# Reward weights
rewards:
  true_positive: 15.0
  false_positive: -12.0
  false_negative: -18.0
  fix_worked: 15.0

  # Calibration and exploration
  calibration_bonus_weight: 10.0
  low_observation_bonus: 5.0

# Attacker rewards
attacker_rewards:
  false_negatives: 15.0
  fixes_broken: 25.0
  novel_exploits: 10.0
```

### Audit Trail Verification

The system maintains tamper-evident logs:

```python
from src.utils.audit import TamperEvidentLogger

# Verify audit log integrity
logger = TamperEvidentLogger("data/audit.log")
is_valid = logger.verify_chain()

if is_valid:
    print("✓ Audit trail verified - no tampering detected")
else:
    print("✗ Tampering detected!")
```

### Pattern Effectiveness Analysis

```python
from src.knowledge.graph import SecurityKnowledgeGraph

kg = SecurityKnowledgeGraph()

# Get most effective patterns
effective = kg.get_effective_patterns(min_effectiveness=0.7)
for pattern in effective:
    print(f"{pattern.id}: {pattern.name}")
    print(f"  Precision: {pattern.precision:.1%}")
    print(f"  Recall: {pattern.recall:.1%}")
    print(f"  F1: {pattern.f1_score:.1%}")
```

## Troubleshooting

### API Key Not Set

**Error:** `ANTHROPIC_API_KEY not set`

**Solution:**
```bash
export ANTHROPIC_API_KEY="your-key-here"
```

### CVEFixes Database Not Found

**Error:** `CVEfixes database not found at data/datasets/CVEfixes.db`

**Solution:**
```bash
python scripts/download_cvefixes.py
```

### Out of Memory

**Error:** Process killed due to memory

**Solution:**
- Reduce batch size in config.yaml
- Evaluate smaller subsets (--limit 50)
- Run in batches

### Rate Limiting

**Error:** API rate limit exceeded

**Solution:**
- Add delay between requests
- Reduce parallel processing
- Use rate limiting in config

### Test Failures

**Error:** Some tests failing

**Solution:**
```bash
# Run specific test file
python -m pytest tests/test_benchmark.py -v

# Check pre-existing failures (RL/API mocking issues are known)
# Should have 92+ passing tests
python -m pytest tests/ -v
```

### Permission Denied

**Error:** Cannot create files in data/

**Solution:**
```bash
# Create directories with proper permissions
mkdir -p data/{episodes,patterns,benchmarks,datasets}
chmod 755 data/
```

## Next Steps

Now that you're set up, explore:

1. **Run Extended Benchmark** (1000 samples)
   - See `docs/BENCHMARKING.md`

2. **Understand the Architecture**
   - Read architecture documentation
   - Review code in `src/`

3. **Contribute Patterns**
   - Add new vulnerability patterns to `src/patterns/library.py`
   - Test with benchmark

4. **Research Validation**
   - Follow roadmap in `AGENT_ANALYSIS_TODO.md`
   - Compare with SOTA models

5. **Compliance**
   - Review `SECURITY.md`, `DATA_POLICY.md`
   - Follow SOPs in `SOP.md`

## Getting Help

- **Documentation:** `/docs` directory
- **Examples:** `/examples` directory
- **Tests:** `/tests` directory (see how features work)
- **Issues:** GitHub issues
- **Papers:** See `/reports` directory for research findings

## Citation

If you use this work in research:

```bibtex
@software{asds_selfplay_2025,
  title={ASDS Self-Play: Adaptive Security Defence System with Adversarial Learning},
  author={Your Name},
  year={2025},
  url={https://github.com/yourusername/asds-selfplay}
}
```

## License

See LICENSE file for details.
