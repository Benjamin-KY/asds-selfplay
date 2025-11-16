# System Architecture

This document describes the technical architecture of the ASDS Self-Play system.

## Table of Contents

1. [Overview](#overview)
2. [Core Components](#core-components)
3. [Data Flow](#data-flow)
4. [Key Algorithms](#key-algorithms)
5. [Database Schema](#database-schema)
6. [API Specifications](#api-specifications)
7. [Security Model](#security-model)

## Overview

ASDS Self-Play is a reinforcement learning system that uses adversarial self-play to improve vulnerability detection without human labeling.

### High-Level Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        ASDS Self-Play                            │
├─────────────────────────────────────────────────────────────────┤
│                                                                   │
│  ┌──────────────┐         ┌──────────────┐                      │
│  │  Training    │         │  Evaluation  │                      │
│  │  Pipeline    │         │  Pipeline    │                      │
│  └──────┬───────┘         └──────┬───────┘                      │
│         │                         │                               │
│         ▼                         ▼                               │
│  ┌─────────────────────────────────────────┐                    │
│  │        Self-Play Orchestration          │                    │
│  │  ┌────────────┐     ┌────────────┐     │                    │
│  │  │ Defender   │◄───►│  Attacker  │     │                    │
│  │  │   Agent    │     │   Agent    │     │                    │
│  │  └──────┬─────┘     └─────┬──────┘     │                    │
│  │         │                  │            │                    │
│  │         └──────────┬───────┘            │                    │
│  │                    ▼                    │                    │
│  │          ┌──────────────────┐          │                    │
│  │          │ Knowledge Graph  │          │                    │
│  │          │  (52 patterns)   │          │                    │
│  │          └──────────────────┘          │                    │
│  └─────────────────────────────────────────┘                    │
│                      │                                           │
│                      ▼                                           │
│  ┌─────────────────────────────────────────┐                    │
│  │    Reinforcement Learning (GRPO)        │                    │
│  │  ┌────────────┐     ┌────────────┐     │                    │
│  │  │RL Store    │     │ RL Trainer │     │                    │
│  │  └────────────┘     └────────────┘     │                    │
│  └─────────────────────────────────────────┘                    │
│                                                                   │
│  ┌─────────────────────────────────────────┐                    │
│  │    Security & Compliance                │                    │
│  │  ┌────────────┐     ┌────────────┐     │                    │
│  │  │Tamper-     │     │  Audit     │     │                    │
│  │  │Evident Log │     │  Trail     │     │                    │
│  │  └────────────┘     └────────────┘     │                    │
│  └─────────────────────────────────────────┘                    │
└─────────────────────────────────────────────────────────────────┘
```

## Core Components

### 1. Knowledge Graph (`src/knowledge/graph.py`)

**Purpose:** Store and track security patterns and their effectiveness.

**Key Classes:**
- `SecurityPattern`: Individual vulnerability pattern with metrics
- `SecurityKnowledgeGraph`: Graph database for patterns

**Pattern Structure:**
```python
@dataclass
class SecurityPattern:
    id: str                    # e.g., "PATTERN-SQL-001"
    name: str                  # Human-readable name
    pattern_type: PatternType  # SQL_INJECTION, XSS, etc.
    code_example: str          # Vulnerable code sample
    language: str              # Programming language
    risk_level: str            # critical, high, medium, low
    cwe_id: Optional[str]      # CWE identifier

    # Learning metrics (updated via RL)
    observations: int          # Total times observed
    true_positives: int        # Confirmed vulnerabilities
    false_positives: int       # False alarms
    false_negatives: int       # Missed vulnerabilities

    # Calibration (Brier score)
    calibration_sum_squared_errors: float
    calibration_count: int

    # Derived metrics
    @property
    def precision(self) -> float
    @property
    def recall(self) -> float
    @property
    def f1_score(self) -> float
    @property
    def effectiveness(self) -> float
    @property
    def brier_score(self) -> float
```

**Database:** SQLite at `data/patterns/knowledge.db`

**Operations:**
- `add_pattern()`: Add new pattern
- `update_pattern_effectiveness()`: Update metrics from feedback
- `get_effective_patterns()`: Retrieve high-performing patterns
- `prune_ineffective_patterns()`: Remove low-performing patterns

### 2. Defender Agent (`src/agents/defender.py`)

**Purpose:** Analyze code and detect vulnerabilities using LLM + learned patterns.

**Key Methods:**
```python
class DefenderAgent:
    def __init__(self, kg: SecurityKnowledgeGraph, rl_store=None):
        self.client = anthropic.Anthropic()
        self.kg = kg
        self.rl_store = rl_store

    def analyze_code(
        self,
        code: str,
        language: str
    ) -> List[Finding]:
        """
        Analyze code for vulnerabilities.

        Returns list of findings with:
        - Vulnerability type and severity
        - Location and code snippet
        - Explanation and fix suggestion
        - Confidence score (0-1)
        """
        # 1. Get effective patterns from knowledge graph
        patterns = self.kg.get_effective_patterns()

        # 2. Build dynamic prompt with patterns
        prompt = self._build_prompt(code, language, patterns)

        # 3. Call LLM
        response = self.client.messages.create(
            model="claude-3-5-sonnet-20241022",
            messages=[{"role": "user", "content": prompt}]
        )

        # 4. Parse findings from response
        findings = self._parse_findings(response.content[0].text)

        # 5. Record trace for RL (if enabled)
        if self.rl_store:
            self.rl_store.record_trace(prompt, findings)

        return findings
```

**Dynamic Prompt Generation:**
```python
def _build_prompt(self, code, language, patterns):
    return f"""
🎯 HIGH-VALUE PATTERNS (proven effective):
{self._format_effective_patterns(patterns)}

⚠️ AVOID FALSE POSITIVES:
{self._format_ineffective_patterns()}

Analyze this {language} code for security vulnerabilities:
{code}

For each finding, provide:
1. Vulnerability type (SQL injection, XSS, etc.)
2. Severity (critical/high/medium/low)
3. Location (line number or function name)
4. Code snippet showing the issue
5. Explanation of the vulnerability
6. Suggested fix
7. Confidence score (0.0-1.0)
"""
```

### 3. Attacker Agent (`src/agents/attacker.py`)

**Purpose:** Validate defender findings by attempting exploitation.

**Key Methods:**
```python
class AttackerAgent:
    def exploit_finding(
        self,
        finding: Finding,
        code: str,
        language: str
    ) -> ExploitResult:
        """
        Attempt to exploit a vulnerability finding.

        Returns:
        - success: bool (True if exploitable)
        - exploit_code: Generated exploit
        - explanation: How the exploit works
        """
        # 1. Build exploitation prompt
        prompt = f"""
You are a security researcher testing this finding:
Type: {finding.type}
Location: {finding.location}
Code: {code}

Generate a proof-of-concept exploit that demonstrates
this vulnerability is real. If you cannot generate a
working exploit, this is likely a false positive.
"""

        # 2. Call LLM
        response = self.client.messages.create(
            model="claude-3-5-sonnet-20241022",
            messages=[{"role": "user", "content": prompt}]
        )

        # 3. Parse exploit result
        return self._parse_exploit(response.content[0].text)

    def test_fix(
        self,
        fixed_code: str,
        exploit_code: str
    ) -> bool:
        """
        Test if a fix actually prevents the exploit.

        Returns True if fix works, False if still exploitable.
        """
        # Test the proposed fix against the exploit
        ...
```

### 4. Self-Play Trainer (`src/core/self_play.py`)

**Purpose:** Orchestrate adversarial training loop.

**Training Episode Flow:**
```python
class SelfPlayTrainer:
    def train_episode(
        self,
        code_sample: str,
        language: str
    ) -> TrainingEpisode:
        """
        Run one training episode.

        Steps:
        1. Defender analyzes code
        2. Defender suggests fixes
        3. Attacker validates findings (TP/FP)
        4. Attacker tests fixes (worked/broken)
        5. Calculate rewards
        6. Update knowledge graph
        7. Save episode data
        """

        # 1. Defender analyzes
        findings = self.defender.analyze_code(code_sample, language)

        # 2. Defender suggests fixes
        fixes = [self.defender.suggest_fix(f) for f in findings]

        # 3. Attacker validates (ground truth)
        validation = [
            self.attacker.exploit_finding(f, code_sample, language)
            for f in findings
        ]

        # 4. Count TP/FP/FN
        tp = sum(1 for v in validation if v.success)
        fp = sum(1 for v in validation if not v.success)
        fn = self._count_false_negatives(code_sample)

        # 5. Test fixes
        fixes_worked = sum(
            1 for fix in fixes
            if not self.attacker.test_fix(fix.code, validation.exploit_code)
        )

        # 6. Calculate reward
        reward = self._calculate_reward({
            'tp': tp, 'fp': fp, 'fn': fn,
            'fixes_worked': fixes_worked
        }, findings)

        # 7. Update patterns
        for finding, valid in zip(findings, validation):
            self.kg.update_pattern_effectiveness(
                pattern_id=finding.pattern_id,
                is_true_positive=valid.success,
                confidence=finding.confidence
            )

        # 8. Save episode
        episode = TrainingEpisode(
            episode_number=self.episode_count,
            reward=reward,
            true_positives=tp,
            false_positives=fp,
            false_negatives=fn,
            findings=findings,
            timestamp=datetime.now()
        )

        self._save_episode(episode)
        self.episode_count += 1

        return episode
```

**Reward Function (Game Theory Optimized):**
```python
def _calculate_reward(self, metrics: Dict, findings: List[Finding]) -> float:
    # Base reward
    reward = (
        15.0 * metrics['tp']        # +50% from baseline
        - 12.0 * metrics['fp']      # +140% penalty (critical fix)
        - 18.0 * metrics['fn']      # +20% penalty
        + 15.0 * metrics['fixes_worked']  # -25% from baseline
    )

    # Calibration bonus (Brier score)
    avg_brier = self._calculate_average_brier_score(findings)
    if avg_brier is not None:
        calibration_bonus = 10.0 * (1.0 - avg_brier)
        reward += calibration_bonus

    # Exploration bonus
    low_obs_patterns = sum(
        1 for f in findings
        if self.kg.patterns[f.pattern_id].observations < 10
    )
    exploration_bonus = 5.0 * low_obs_patterns
    reward += exploration_bonus

    return reward
```

### 5. Benchmark Evaluation (`src/evaluation/benchmark.py`)

**Purpose:** Evaluate performance on real-world datasets.

**Key Classes:**
```python
class BenchmarkRunner:
    def run_cvefixes_benchmark(
        self,
        db_path: str,
        language: str = "python",
        limit: int = 100
    ) -> Tuple[List[BenchmarkResult], BenchmarkSummary]:
        """
        Evaluate defender on CVEFixes dataset.

        Returns:
        - results: Per-sample results
        - summary: Aggregate metrics (precision, recall, F1)
        """

        # 1. Load samples from CVEFixes
        loader = CVEFixesLoader(db_path)
        samples = loader.load_samples(language=language, limit=limit)

        # 2. Evaluate each sample
        results = []
        for sample in samples:
            # Defender analyzes vulnerable code
            findings = self.defender.analyze_code(
                sample.vulnerable_code,
                sample.programming_language
            )

            # Classify result
            detected = len(findings) > 0
            true_positive = detected  # All CVEFixes samples are vulnerable
            false_negative = not detected

            results.append(BenchmarkResult(
                sample_id=sample.cve_id,
                cwe_id=sample.cwe_id,
                detected=detected,
                true_positive=true_positive,
                false_negative=false_negative,
                findings=findings,
                confidence_scores=[f.confidence for f in findings]
            ))

        # 3. Generate summary
        summary = self._generate_summary(results)

        return results, summary
```

**Metrics Calculation:**
```python
def _generate_summary(self, results: List[BenchmarkResult]) -> BenchmarkSummary:
    tp = sum(1 for r in results if r.true_positive)
    fp = sum(1 for r in results if r.false_positive)
    fn = sum(1 for r in results if r.false_negative)

    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0

    return BenchmarkSummary(
        total_samples=len(results),
        true_positives=tp,
        false_positives=fp,
        false_negatives=fn,
        precision=precision,
        recall=recall,
        f1_score=f1,
        ...
    )
```

### 6. Reinforcement Learning (`src/rl/`)

**GRPO Algorithm:**
- Group Relative Policy Optimization
- No model fine-tuning required
- Updates prompts based on relative rewards
- Manages pattern selection strategy

**Components:**
- `LightningStore`: Stores RL traces and rewards
- `Trainer`: Applies GRPO updates
- `GRPO`: Core algorithm implementation

### 7. Tamper-Evident Logging (`src/utils/audit.py`)

**Purpose:** Cryptographically secure audit trail.

**Implementation:**
```python
class TamperEvidentLogger:
    def sign_episode(self, episode_data: Dict) -> Dict:
        """
        Sign episode with HMAC-SHA256.

        Creates hash chain:
        signature_n = HMAC(data_n + signature_n-1)
        """
        # 1. Hash episode data
        data_hash = hashlib.sha256(
            json.dumps(episode_data, sort_keys=True).encode()
        ).hexdigest()

        # 2. Create chain data (includes previous hash)
        chain_data = {
            "data_hash": data_hash,
            "previous_hash": self.previous_hash,
            "timestamp": datetime.now().isoformat()
        }

        # 3. Sign with HMAC
        signature = hmac.new(
            self.secret_key,
            json.dumps(chain_data, sort_keys=True).encode(),
            hashlib.sha256
        ).hexdigest()

        # 4. Update chain
        self.previous_hash = signature

        return {
            "data_hash": data_hash,
            "signature": signature,
            "previous_hash": chain_data["previous_hash"],
            "timestamp": chain_data["timestamp"]
        }

    def verify_chain(self) -> bool:
        """Verify entire audit log integrity."""
        # Verify each entry's signature
        # Verify chain linkage
        # Detect any tampering
        ...
```

## Data Flow

### Training Episode Data Flow

```
1. Code Sample
   ↓
2. Defender Agent
   ├─→ Get effective patterns from Knowledge Graph
   ├─→ Build dynamic prompt
   ├─→ Call LLM
   └─→ Parse findings
   ↓
3. Attacker Agent
   ├─→ Validate each finding (exploit)
   └─→ Test each fix (re-exploit)
   ↓
4. Metrics Calculation
   ├─→ Count TP/FP/FN
   ├─→ Calculate reward
   └─→ Calculate Brier score
   ↓
5. Knowledge Graph Update
   ├─→ Update pattern metrics
   └─→ Adjust effectiveness scores
   ↓
6. Episode Storage
   ├─→ Sign with HMAC
   ├─→ Add to hash chain
   └─→ Save to data/episodes/
   ↓
7. RL Update (if enabled)
   ├─→ Store trace in RL store
   └─→ Apply GRPO update
```

### Benchmark Evaluation Data Flow

```
1. CVEFixes Database
   ↓
2. CVEFixesLoader
   ├─→ Query vulnerable methods
   └─→ Filter by language/CWE
   ↓
3. Defender Agent (for each sample)
   ├─→ Analyze vulnerable code
   └─→ Generate findings
   ↓
4. Classification
   ├─→ TP: Vulnerability detected
   └─→ FN: Vulnerability missed
   ↓
5. Results Aggregation
   ├─→ Calculate precision/recall/F1
   ├─→ Per-CWE breakdown
   └─→ Generate summary
   ↓
6. Save Results
   └─→ JSON file in data/benchmarks/
```

## Key Algorithms

### Pattern Effectiveness Calculation

```python
def calculate_effectiveness(pattern: SecurityPattern) -> float:
    """
    Effectiveness = F1 score (if enough data)

    F1 = 2 * (precision * recall) / (precision + recall)
    Precision = TP / (TP + FP)
    Recall = TP / (TP + FN)
    """
    if pattern.observations < 3:
        return 0.5  # Neutral for new patterns

    precision = pattern.precision
    recall = pattern.recall

    if precision + recall == 0:
        return 0.0

    return 2 * (precision * recall) / (precision + recall)
```

### Brier Score (Calibration)

```python
def calculate_brier_score(predictions: List[Tuple[float, bool]]) -> float:
    """
    Brier Score = average of (confidence - actual)^2

    0.0 = perfect calibration
    1.0 = worst calibration

    Rewards honest uncertainty reporting.
    """
    squared_errors = [
        (confidence - float(actual)) ** 2
        for confidence, actual in predictions
    ]

    return sum(squared_errors) / len(squared_errors)
```

### Nash Equilibrium (Game Theory)

The reward weights are designed to create a Nash equilibrium where neither agent can improve by changing strategy:

**Defender:**
- Maximize: TP (find real vulnerabilities)
- Minimize: FP (avoid false alarms)
- Minimize: FN (don't miss vulnerabilities)

**Attacker:**
- Maximize: FN (find what defender missed)
- Minimize: TP (avoid being detected)
- Maximize: Breaking fixes (high value)

**Equilibrium:** Both agents playing optimally leads to:
- High detection rate
- Low false positive rate
- Robust fixes

## Database Schema

### Knowledge Graph (SQLite)

**patterns table:**
```sql
CREATE TABLE patterns (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    pattern_type TEXT NOT NULL,
    code_example TEXT NOT NULL,
    language TEXT NOT NULL,
    risk_level TEXT NOT NULL,
    cwe_id TEXT,
    observations INTEGER DEFAULT 0,
    true_positives INTEGER DEFAULT 0,
    false_positives INTEGER DEFAULT 0,
    false_negatives INTEGER DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
)
```

**pattern_relationships table:**
```sql
CREATE TABLE pattern_relationships (
    source_id TEXT NOT NULL,
    target_id TEXT NOT NULL,
    relationship_type TEXT NOT NULL,
    weight REAL DEFAULT 1.0,
    PRIMARY KEY (source_id, target_id, relationship_type),
    FOREIGN KEY (source_id) REFERENCES patterns(id),
    FOREIGN KEY (target_id) REFERENCES patterns(id)
)
```

### CVEFixes Database Schema

See CVEFixes documentation for full schema. Key tables:
- `cve`: CVE metadata
- `file_change`: Changed files in fixes
- `method_change`: Method-level code changes
- `cwe`: CWE classifications

## API Specifications

### Anthropic Claude API

**Model:** `claude-3-5-sonnet-20241022`

**Request:**
```python
response = client.messages.create(
    model="claude-3-5-sonnet-20241022",
    max_tokens=4096,
    temperature=0.0,  # Deterministic for consistency
    messages=[
        {"role": "user", "content": prompt}
    ]
)
```

**Response:**
```python
{
    "content": [
        {
            "type": "text",
            "text": "..."
        }
    ],
    "usage": {
        "input_tokens": 1234,
        "output_tokens": 567
    }
}
```

## Security Model

### Threat Model

**Threats:**
1. **Data Tampering:** Modify episode history to hide failures
2. **Injection Attacks:** Malicious code in samples
3. **API Key Exposure:** Leaked credentials
4. **Unauthorized Access:** Access to sensitive data

**Mitigations:**
1. **Tamper-Evident Logging:** HMAC signatures + hash chains
2. **Input Validation:** Sanitize all code samples
3. **Secret Management:** Environment variables, never logged
4. **Access Controls:** File permissions (600/700)

### Security Controls

| Control | Status | Implementation |
|---------|--------|----------------|
| Cryptographic Signatures | ✅ Implemented | HMAC-SHA256 |
| Hash Chains | ✅ Implemented | SHA-256 |
| Audit Trail | ✅ Implemented | Append-only log |
| Access Controls | ⏳ Planned | RBAC |
| Encryption at Rest | ⏳ Planned | AES-256-GCM |
| Input Validation | ⏳ Planned | Sandboxing |

See `SECURITY.md` for complete threat model and security controls.

## Performance Characteristics

### Scalability

**Training:**
- Time per episode: ~10-30 seconds (depends on code size)
- API cost per episode: ~$0.01-0.05
- 100 episodes: ~30-60 minutes, $1-5
- 1000 episodes: ~5-10 hours, $10-50

**Benchmarking:**
- Time per sample: ~2-5 seconds
- 100 samples: ~5-10 minutes
- 1000 samples: ~1-2 hours

**Database:**
- Knowledge graph: <10 MB
- Episode history (1000 episodes): ~50-100 MB
- CVEFixes dataset: ~2-3 GB

### Optimization Opportunities

1. **Caching:** Cache LLM responses for identical code
2. **Batching:** Batch multiple samples per API call
3. **Parallel Processing:** Run defender on multiple samples concurrently
4. **Pattern Pruning:** Remove ineffective patterns regularly

## Future Enhancements

See `AGENT_ANALYSIS_TODO.md` for complete roadmap:
- Multi-language support (JavaScript, Java, Go)
- SOTA comparison framework
- Access controls and authentication
- Encryption at rest
- Web dashboard
- Real-time monitoring

## References

- Game Theory Analysis: `/reports/game-theory-analysis.md`
- Research Findings: `/reports/research-findings.md`
- Compliance Review: `/reports/compliance-review.md`
- CVEFixes Paper: https://dl.acm.org/doi/10.1145/3475960.3475985
- GRPO Algorithm: Group Relative Policy Optimization literature
