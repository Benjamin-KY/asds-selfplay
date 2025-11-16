# ASDS Self-Play Architecture

## Overview

This document describes the technical architecture of the Adaptive Security Defence System v2, which uses adversarial self-play and reinforcement learning to continuously improve security analysis.

## Design Principles

1. **No Model Fine-Tuning:** Use in-context learning via dynamic prompts
2. **Automated Feedback:** Attacker agents provide ground truth
3. **Measurable Learning:** Track objective metrics (attack success rates)
4. **Framework Agnostic:** Works with any LLM via prompt engineering
5. **Scalable Training:** Unlimited self-play episodes

## Component Architecture

### 1. Knowledge Graph

**Purpose:** Track security patterns and learn their effectiveness

**Schema:**
```python
class SecurityPattern:
    id: str                    # Unique pattern identifier
    name: str                  # Human-readable name
    pattern_type: str          # sql_injection, xss, command_injection, etc.
    code_example: str          # Example of vulnerable code
    language: str              # python, javascript, etc.
    risk_level: str            # critical, high, medium, low

    # Learning metrics (updated via RL)
    observations: int          # Times this pattern was checked
    true_positives: int        # Times attacker confirmed vulnerability
    false_positives: int       # Times attacker couldn't exploit
    false_negatives: int       # Times attacker found but defender missed

    # Derived metrics
    precision: float           # TP / (TP + FP)
    recall: float              # TP / (TP + FN)
    effectiveness: float       # F1 score or custom metric

    # RL state
    last_reward: float         # Most recent reward signal
    cumulative_reward: float   # Sum of all rewards
    confidence_interval: float # Statistical confidence
```

**Graph Structure:**
```
Patterns ──MANIFESTS_AS──> Vulnerabilities (CWEs)
Patterns ──SEEN_IN──> Languages/Frameworks
Patterns ──SIMILAR_TO──> Other Patterns
Vulnerabilities ──MITIGATED_BY──> Fix Patterns
Vulnerabilities ──EXPLOITED_BY──> Attack Techniques
```

**Learning Algorithm:**
```python
def update_pattern(pattern_id, attacker_result):
    pattern = graph.get_pattern(pattern_id)
    pattern.observations += 1

    if attacker_result.exploited:
        if pattern_id in defender_findings:
            pattern.true_positives += 1  # Defender caught it
        else:
            pattern.false_negatives += 1  # Defender missed it
    else:
        if pattern_id in defender_findings:
            pattern.false_positives += 1  # False alarm

    # Update effectiveness score
    pattern.effectiveness = calculate_f1(
        precision=pattern.true_positives / (pattern.true_positives + pattern.false_positives),
        recall=pattern.true_positives / (pattern.true_positives + pattern.false_negatives)
    )

    # Prune if consistently ineffective
    if pattern.observations > 20 and pattern.effectiveness < 0.2:
        graph.deprecate_pattern(pattern_id)
```

### 2. Dynamic Prompt Generator

**Purpose:** Build prompts with in-context learning from knowledge graph

**Strategy:**
```python
def generate_analysis_prompt(code: str, context: dict) -> str:
    # Fetch learned patterns
    effective_patterns = knowledge_graph.get_patterns(
        min_effectiveness=0.7,
        limit=5,
        language=context.get('language')
    )

    recent_discoveries = knowledge_graph.get_patterns(
        sort_by='recent',
        limit=3
    )

    false_positive_traps = knowledge_graph.get_patterns(
        max_effectiveness=0.3,
        min_observations=10
    )

    # Build few-shot prompt
    prompt = f"""You are a security analyst. Based on {knowledge_graph.total_observations} past analyses:

✅ EFFECTIVE PATTERNS (prioritize these):
{format_patterns_with_examples(effective_patterns)}

🆕 RECENTLY DISCOVERED:
{format_patterns_with_examples(recent_discoveries)}

❌ AVOID FALSE POSITIVES:
These patterns have high false positive rates - be skeptical:
{format_patterns_with_examples(false_positive_traps)}

CODE TO ANALYZE:
```{context.get('language', 'python')}
{code}
```

TASK:
1. Check for effective patterns first (highest ROI)
2. Look for recently discovered patterns (may be relevant)
3. Avoid patterns known to cause false alarms
4. Report findings with confidence scores

FORMAT:
{json_schema}
"""
    return prompt
```

**Advantages:**
- Prompts improve as knowledge graph learns
- No model retraining required
- Can swap LLMs easily
- Immediate feedback incorporation

### 3. Defender Agent

**Purpose:** Analyze code and suggest fixes using learned patterns

**Interface:**
```python
class DefenderAgent:
    def __init__(self, knowledge_graph, llm_client):
        self.kg = knowledge_graph
        self.llm = llm_client
        self.prompt_generator = DynamicPromptGenerator(knowledge_graph)

    def analyze(self, code: str, context: dict) -> DefenseTrace:
        """Analyze code for vulnerabilities"""

        # Generate prompt with learned patterns
        prompt = self.prompt_generator.generate(code, context)

        # LLM analysis
        response = self.llm.analyze(prompt)

        # Parse findings
        findings = self.parse_findings(response)

        # Create trace for Agent Lightning
        trace = DefenseTrace(
            code=code,
            prompt=prompt,
            findings=findings,
            timestamp=datetime.now()
        )

        return trace

    def suggest_fixes(self, findings: List[Finding]) -> List[Fix]:
        """Suggest fixes for identified vulnerabilities"""

        fixes = []
        for finding in findings:
            # Get mitigation patterns from knowledge graph
            mitigations = self.kg.get_mitigations(finding.cwe_id)

            # Generate fix using LLM + learned mitigations
            fix = self.llm.generate_fix(
                finding=finding,
                mitigations=mitigations
            )

            fixes.append(fix)

        return fixes
```

**Output:**
```python
DefenseTrace {
    findings: [
        {
            id: "find-001",
            type: "SQL Injection",
            cwe_id: "CWE-89",
            severity: "critical",
            location: "line 42",
            pattern_id: "PATTERN-001",  # Which pattern detected it
            confidence: 0.95,
            explanation: "...",
            suggested_fix: "..."
        }
    ],
    patterns_checked: 15,
    time_taken: 2.3
}
```

### 4. Attacker Agent

**Purpose:** Generate exploits and test defenses (ground truth provider)

**Interface:**
```python
class AttackerAgent:
    def __init__(self, exploit_db, llm_client):
        self.exploits = exploit_db
        self.llm = llm_client

    def attack(self, code: str, context: dict) -> AttackTrace:
        """Attempt to exploit code"""

        successful_exploits = []

        # 1. Try known exploit patterns
        for exploit_type in ['sqli', 'xss', 'cmd_injection', 'path_traversal']:
            result = self.try_exploit(code, exploit_type)
            if result.success:
                successful_exploits.append(result)

        # 2. Use LLM to discover novel exploits
        novel_exploits = self.llm_discover_exploits(code)
        successful_exploits.extend(novel_exploits)

        # 3. Test with fuzzing
        fuzz_results = self.fuzz_test(code)
        successful_exploits.extend(fuzz_results)

        return AttackTrace(
            code=code,
            exploits=successful_exploits,
            attempts=self.total_attempts,
            timestamp=datetime.now()
        )

    def verify_fix(self, original_code: str, fixed_code: str,
                   original_exploits: List[Exploit]) -> FixVerification:
        """Test if fixes actually work"""

        still_vulnerable = []

        for exploit in original_exploits:
            # Try same exploit on fixed code
            result = self.try_exploit(fixed_code, exploit.type)
            if result.success:
                still_vulnerable.append(exploit)

        return FixVerification(
            fixed_count=len(original_exploits) - len(still_vulnerable),
            still_vulnerable=still_vulnerable
        )
```

**Exploit Strategies:**

1. **Rule-Based:** Known patterns (SQLi, XSS, etc.)
2. **LLM-Powered:** Creative exploit generation
3. **Fuzzing:** Random input mutation
4. **CVE Database:** Known vulnerability patterns

**Output:**
```python
AttackTrace {
    exploits: [
        {
            type: "SQL Injection",
            payload: "' OR 1=1--",
            target: "login function",
            success: True,
            impact: "Authentication bypass",
            cwe_id: "CWE-89"
        }
    ],
    total_attempts: 47,
    success_rate: 0.21
}
```

### 5. Self-Play Training Loop

**Purpose:** Orchestrate defender vs attacker episodes for learning

**Algorithm:**
```python
class SelfPlayTrainer:
    def train_episode(self, code_sample: str):
        """Single training episode"""

        # Phase 1: Defense
        print(f"🛡️  Defender analyzing...")
        defense_trace = self.defender.analyze(code_sample)

        # Phase 2: Attack original code
        print(f"⚔️  Attacker exploiting original...")
        attack_trace = self.attacker.attack(code_sample)

        # Phase 3: Defender fixes
        if defense_trace.findings:
            print(f"🔧 Defender applying fixes...")
            fixes = self.defender.suggest_fixes(defense_trace.findings)
            fixed_code = apply_fixes(code_sample, fixes)
        else:
            fixed_code = code_sample

        # Phase 4: Attack fixed code
        print(f"⚔️  Attacker testing fixes...")
        attack_fixed = self.attacker.attack(fixed_code)

        # Phase 5: Calculate reward
        reward = self.calculate_reward(
            defender_findings=defense_trace.findings,
            original_exploits=attack_trace.exploits,
            fixed_exploits=attack_fixed.exploits
        )

        print(f"📊 Reward: {reward:.2f}")

        # Phase 6: Update knowledge graph
        self.update_knowledge_graph(
            defense_trace=defense_trace,
            attack_trace=attack_trace,
            reward=reward
        )

        # Phase 7: Emit traces to Agent Lightning
        self.lightning.emit_trace('defender', defense_trace, reward)

        return TrainingResult(
            reward=reward,
            vulnerabilities_found=len(defense_trace.findings),
            vulnerabilities_fixed=len(attack_trace.exploits) - len(attack_fixed.exploits),
            false_positives=calculate_fp(defense_trace, attack_trace)
        )
```

**Reward Function:**
```python
def calculate_reward(defender_findings, original_exploits, fixed_exploits):
    # True positives: defender found and attacker confirmed
    tp = len([f for f in defender_findings
              if any(e.cwe_id == f.cwe_id for e in original_exploits)])

    # False positives: defender flagged but attacker couldn't exploit
    fp = len(defender_findings) - tp

    # False negatives: attacker found but defender missed
    fn = len([e for e in original_exploits
              if not any(f.cwe_id == e.cwe_id for f in defender_findings)])

    # Fixes that worked: exploits blocked after fix
    fixes_worked = len(original_exploits) - len(fixed_exploits)

    # Reward formula
    reward = (
        +10.0 * tp              # Correctly identified vulnerabilities
        -5.0 * fp               # Penalty for false alarms
        -8.0 * fn               # Penalty for missed vulnerabilities
        +15.0 * fixes_worked    # Bonus for working fixes
        -3.0 * len(fixed_exploits)  # Penalty if fixes didn't work
    )

    return reward
```

### 6. Agent Lightning Integration

**Purpose:** RL orchestration and prompt optimization

**Integration Points:**
```python
from agentlightning import LightningStore, Trainer

# Create store
store = LightningStore()

# Wrap defender with trace emission
@store.trace("defender")
def defender_analyze(code):
    return defender.analyze(code)

# Collect rewards from self-play
for episode in episodes:
    trace = defender_analyze(code)
    reward = self_play.calculate_reward(trace)
    store.emit_reward(trace.id, reward)

# Train to optimize prompts/strategies
trainer = Trainer(store, algorithm="GRPO")
trainer.train(iterations=1000)
```

**What Agent Lightning Optimizes:**
- Prompt template selection
- Pattern prioritization strategy
- Confidence thresholds
- Analysis depth vs speed tradeoffs

### 7. Metrics System

**Purpose:** Track learning progress and system effectiveness

**Tracked Metrics:**
```python
class Metrics:
    # Detection metrics
    true_positive_rate: float   # Sensitivity/Recall
    false_positive_rate: float  # 1 - Specificity
    precision: float            # Positive Predictive Value
    f1_score: float             # Harmonic mean of precision/recall

    # Learning metrics
    episode_number: int
    cumulative_reward: float
    average_reward: float
    reward_trend: List[float]   # Last 100 episodes

    # Pattern metrics
    active_patterns: int
    deprecated_patterns: int
    pattern_effectiveness_avg: float

    # Performance metrics
    analysis_time_avg: float
    patterns_checked_avg: float

    # Adversarial metrics
    attacker_success_rate: float
    defense_effectiveness: float  # % of attacks blocked
    fix_success_rate: float       # % of fixes that work
```

**Visualization:**
```
Episode 1:     █░░░░░░░░░ 10% Defense Effectiveness
Episode 100:   ████░░░░░░ 40% Defense Effectiveness
Episode 500:   ███████░░░ 70% Defense Effectiveness
Episode 1000:  █████████░ 90% Defense Effectiveness
```

## Data Flow

```
1. Training Data
   ↓
2. Defender Agent
   ├─> Analyzes code
   ├─> Uses learned patterns (from Knowledge Graph)
   └─> Generates findings
   ↓
3. Attacker Agent
   ├─> Attempts exploits
   ├─> Tests findings validity
   └─> Provides ground truth
   ↓
4. Reward Calculation
   ├─> TP, FP, FN counts
   ├─> Fix effectiveness
   └─> Performance metrics
   ↓
5. Knowledge Graph Update
   ├─> Update pattern statistics
   ├─> Adjust effectiveness scores
   └─> Prune ineffective patterns
   ↓
6. Agent Lightning
   ├─> Collects traces
   ├─> Optimizes strategies
   └─> Improves prompts
   ↓
7. Next Episode (improved)
```

## Storage Schema

### SQLite Database
```sql
CREATE TABLE patterns (
    id TEXT PRIMARY KEY,
    name TEXT,
    pattern_type TEXT,
    code_example TEXT,
    language TEXT,
    observations INTEGER DEFAULT 0,
    true_positives INTEGER DEFAULT 0,
    false_positives INTEGER DEFAULT 0,
    false_negatives INTEGER DEFAULT 0,
    effectiveness REAL DEFAULT 0.5,
    last_updated TIMESTAMP
);

CREATE TABLE episodes (
    id TEXT PRIMARY KEY,
    episode_number INTEGER,
    code_sample TEXT,
    defender_findings INTEGER,
    attacker_exploits INTEGER,
    reward REAL,
    timestamp TIMESTAMP
);

CREATE TABLE findings (
    id TEXT PRIMARY KEY,
    episode_id TEXT,
    pattern_id TEXT,
    is_true_positive BOOLEAN,
    confidence REAL,
    FOREIGN KEY (episode_id) REFERENCES episodes(id),
    FOREIGN KEY (pattern_id) REFERENCES patterns(id)
);
```

## Scalability Considerations

1. **Parallel Episodes:** Run multiple self-play episodes concurrently
2. **Distributed Training:** Use multiple attacker strategies in parallel
3. **Pattern Caching:** Cache frequently used patterns
4. **Incremental Learning:** Update knowledge graph incrementally
5. **Checkpointing:** Save state every N episodes

## Security & Safety

1. **Sandboxed Execution:** Attacker runs in isolated environment
2. **Rate Limiting:** Prevent resource exhaustion
3. **Audit Logging:** Track all exploit attempts
4. **Human Review:** Option to review high-impact findings
5. **Rollback:** Can revert to previous knowledge graph state

## Future Enhancements

1. **Multi-Language Support:** Extend beyond Python
2. **Custom Exploit Generators:** Plugin architecture for attackers
3. **Collaborative Learning:** Share learned patterns across instances
4. **Active Learning:** Prioritize uncertain cases for human review
5. **Transfer Learning:** Apply patterns across different codebases
