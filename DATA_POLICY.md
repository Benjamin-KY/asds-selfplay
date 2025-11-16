# Data Policy

## Overview

This document describes how ASDS Self-Play collects, processes, stores, and protects data during training and operation.

**Version:** 2.0
**Last Updated:** 2025-01-16
**Status:** Research/Development

## Data Collection

### What Data We Collect

#### 1. Code Samples (Input Data)

**Type:** Source code for vulnerability analysis

**Source:**
- User-provided code samples
- Public vulnerability datasets (CVEFixes, DiverseVul)
- CTF challenges
- Synthetic test cases

**Contents:**
- Source code text (Python, JavaScript, etc.)
- Language identifiers
- Optional metadata (file paths, authors, timestamps)

**Sensitivity:** HIGH
- May contain proprietary logic
- May include comments with sensitive information
- May reveal internal architecture

#### 2. Vulnerability Findings (Analysis Results)

**Type:** Defender agent output

**Contents:**
- Vulnerability type (SQL injection, XSS, etc.)
- CWE identifiers
- Severity ratings
- Code locations
- Suggested fixes
- Confidence scores

**Sensitivity:** CRITICAL
- Reveals security weaknesses
- Could be exploited if leaked
- Competitive intelligence value

#### 3. Exploit Attempts (Attack Results)

**Type:** Attacker agent output

**Contents:**
- Exploit types discovered
- Attack vectors used
- Success/failure indicators
- Exploit payloads (sanitized)

**Sensitivity:** CRITICAL
- Active exploit techniques
- Zero-day potential
- Weaponizable information

#### 4. Training Episodes

**Type:** Self-play session data

**Contents:**
- Episode number
- Code sample analyzed
- Defender findings
- Attacker exploits
- Reward calculations
- Metrics (TP/FP/FN)
- Timestamps

**Sensitivity:** HIGH
- Complete training history
- Performance metrics
- Learning curve data

#### 5. Knowledge Graph Patterns

**Type:** Learned security patterns

**Contents:**
- Pattern definitions
- Code examples
- Effectiveness metrics (precision, recall, F1)
- CWE mappings
- Calibration statistics

**Sensitivity:** HIGH
- Proprietary ML knowledge
- Competitive advantage
- Research IP

#### 6. Audit Logs

**Type:** Tamper-evident activity records

**Contents:**
- Episode signatures (HMAC-SHA256)
- Data hashes (SHA-256)
- Timestamps
- Chain linkage
- Metadata (rewards, metrics)

**Sensitivity:** MEDIUM
- Compliance evidence
- Forensic data
- Integrity proof

#### 7. LLM Interactions

**Type:** Prompts and responses

**Contents:**
- Generated prompts (with code samples)
- LLM responses (findings, exploits, fixes)
- Model parameters (temperature, max_tokens)
- API call metadata

**Sensitivity:** HIGH
- Includes code samples (see #1)
- Reveals prompt engineering techniques
- May contain PII in code comments

**Third-Party Sharing:** YES
- Data sent to Anthropic API (Claude)
- See: https://www.anthropic.com/privacy

### What Data We DON'T Collect

- ❌ User identity information (no login required)
- ❌ Network traffic or IP addresses
- ❌ Browser fingerprints or tracking cookies
- ❌ Payment information
- ❌ Personal Identifiable Information (PII)
- ❌ Telemetry or usage analytics

**Exception:** Code samples MAY contain PII in comments/strings (user's responsibility to sanitize)

## Data Storage

### Storage Locations

```
data/
├── episodes/          # Training episodes (JSON files)
│   ├── episode_0001.json
│   ├── episode_0002.json
│   └── ...
├── patterns/          # Knowledge graph (SQLite)
│   └── knowledge.db
├── audit/             # Tamper-evident logs
│   └── audit.log
├── checkpoints/       # RL training checkpoints
│   └── checkpoint_*.pt
└── rl_store.db       # RL traces and rewards
```

### Storage Duration

| Data Type | Default Retention | Configurable | Rationale |
|-----------|------------------|--------------|-----------|
| Episodes | 90 days | Yes | Research analysis period |
| Audit logs | Indefinite | No | Compliance requirement |
| Patterns | Indefinite | Yes | Core learning asset |
| Checkpoints | 30 days | Yes | Recovery window |
| RL traces | 7 days | Yes | Training memory |

**Configuration:**
```yaml
# config.yaml
training:
  episode_retention_days: 90
  checkpoint_retention_days: 30
  rl_trace_retention_days: 7
```

### Storage Security

**Current State (v2.0):**
- ✅ Audit logs: Cryptographically signed (HMAC-SHA256)
- ✅ Audit logs: Hash-chained for tamper detection
- ⚠️ Episode data: Plaintext JSON files
- ⚠️ Database files: Unencrypted SQLite
- ⚠️ File permissions: OS default (no hardening)

**Planned (v2.1):**
- Encryption at rest (AES-256-GCM)
- Encrypted database connections
- Restrictive file permissions (0600)
- Secure key management

### Backup & Recovery

**Recommended Backup:**
```bash
# Backup critical data
tar -czf backup_$(date +%Y%m%d).tar.gz \
  data/patterns/ \
  data/audit/ \
  config.yaml

# Exclude temporary data
tar --exclude='data/episodes/*' \
    --exclude='data/checkpoints/*' \
    -czf backup_minimal.tar.gz data/
```

**Recovery:**
```bash
tar -xzf backup_YYYYMMDD.tar.gz
```

**Backup Frequency:**
- **Audit logs:** Daily (critical for compliance)
- **Patterns:** Daily (research IP)
- **Episodes:** Weekly (can be regenerated)
- **Checkpoints:** Weekly (training snapshots)

## Data Processing

### How We Use Your Data

#### Research & Development
- Train defender agents to detect vulnerabilities
- Train attacker agents to validate findings
- Improve pattern effectiveness via reinforcement learning
- Evaluate detection accuracy (precision, recall, F1)
- Research adversarial learning techniques

#### Pattern Learning
- Extract security patterns from findings
- Calculate pattern effectiveness metrics
- Prune ineffective patterns
- Build knowledge graph relationships
- Generate dynamic prompts for in-context learning

#### Performance Analysis
- Track learning progress over episodes
- Measure reward improvements
- Analyze TP/FP/FN trends
- Evaluate calibration quality (Brier score)
- Generate training visualizations

### Processing Principles

**1. Purpose Limitation**
- Data used ONLY for stated research purposes
- No marketing, advertising, or profiling
- No sale or commercial licensing of data

**2. Data Minimization**
- Collect only what's necessary for training
- No extraneous metadata collection
- Automatic cleanup of old episodes

**3. Transparency**
- This policy documents all data practices
- Open-source codebase for verification
- Audit logs provide complete trail

**4. Security**
- Cryptographic protections (HMAC signatures)
- Tamper-evident audit logging
- Planned encryption at rest

## Third-Party Data Sharing

### LLM Provider (Anthropic)

**What is shared:**
- Code samples (in prompts)
- Vulnerability analysis requests
- Exploit generation requests

**Provider:** Anthropic (Claude API)

**Privacy Policy:** https://www.anthropic.com/privacy

**Data Processing:**
- Prompts sent to Anthropic servers
- Responses returned to ASDS
- Anthropic may log for API monitoring
- NOT used for model training (per Anthropic policy)

**User Control:**
- Disable API logging: Set `anthropic_log_requests: false` (if supported)
- Use self-hosted LLM: Configure custom endpoint in `config.yaml`

### Public Datasets

**CVEFixes Dataset:**
- Source: Public GitHub commits
- Usage: Training data for validation
- License: MIT / Research use
- PII Risk: LOW (public code only)

**DiverseVul Dataset:**
- Source: Academic research dataset
- Usage: Benchmark testing
- License: Research use only
- PII Risk: LOW (sanitized)

**No other third parties** have access to your data.

## Data Rights

### For Researchers Using This Tool

**Your Rights:**
1. **Access:** View all data via `data/` directory
2. **Deletion:** Delete episodes, patterns, or entire database
3. **Export:** JSON format for portability
4. **Correction:** Edit config or re-train patterns

**Your Responsibilities:**
1. **Code Ownership:** Ensure you have rights to analyze code samples
2. **Sensitive Data:** Sanitize PII before processing
3. **Confidential Code:** Don't process if prohibited by license/NDA
4. **Third-Party Data:** Review Anthropic's terms before use

### For Code Sample Contributors

If you provide code samples for analysis:

**Your Rights:**
1. Request deletion of specific samples
2. Request exclusion from pattern learning
3. Review findings before storage

**How to Exercise:**
- Delete episode file: `rm data/episodes/episode_XXXX.json`
- Contact maintainer for pattern exclusion

## Data Subject Requests

### GDPR (if applicable)

ASDS Self-Play does not collect PII by default. However, if PII is inadvertently included in code samples:

**Right to Access:**
```bash
# Search for specific identifier
grep -r "email@example.com" data/episodes/
```

**Right to Erasure:**
```bash
# Remove specific episode
rm data/episodes/episode_XXXX.json

# Remove from audit log (requires manual edit - contact admin)
```

**Right to Rectification:**
- Edit episode JSON file manually
- Re-analyze with corrected code

**Right to Object:**
- Don't process code samples containing PII
- Sanitize before analysis

### CCPA (if applicable)

California residents:

**Do Not Sell:** We do NOT sell your data. Period.

**Data Categories Collected:** See "What Data We Collect" above

**Opt-Out:** N/A (no selling occurs)

## Data Minimization

### Reducing Data Exposure

**Before Analysis:**
```python
# Remove PII from code samples
def sanitize_code(code: str) -> str:
    # Remove email addresses
    code = re.sub(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
                  'EMAIL_REDACTED', code)
    # Remove API keys (simple heuristic)
    code = re.sub(r'["\']sk-[a-zA-Z0-9]{32,}["\']',
                  '"API_KEY_REDACTED"', code)
    return code
```

**Configure Retention:**
```yaml
# config.yaml
training:
  episode_retention_days: 30  # Reduce from default 90
  auto_cleanup: true          # Enable automatic deletion
```

**Selective Storage:**
```python
# Only save high-value episodes
if episode.true_positives > 0 or episode.novel_exploit_types > 0:
    trainer._save_episode(episode)
```

## Data Breach Response

### In Case of Breach

**Immediate Actions:**
1. Stop all training immediately
2. Isolate affected systems
3. Verify audit chain integrity
4. Identify compromised data

**Notification:**
- **Timeline:** Within 72 hours of discovery
- **Recipients:** Affected researchers, code contributors
- **Content:** What data, how exposed, mitigation steps

**Remediation:**
1. Restore from verified backup
2. Patch vulnerability
3. Rotate all credentials (ASDS_AUDIT_SECRET_KEY, API keys)
4. Re-verify audit chain
5. Document incident

### Breach Prevention

**Best Practices:**
- Store `ASDS_AUDIT_SECRET_KEY` in secure vault (e.g., HashiCorp Vault)
- Use restrictive file permissions (0600 for sensitive files)
- Run in isolated environment (Docker, VM)
- Enable audit chain verification on startup
- Monitor for unauthorized access

## Data Portability

### Export Formats

**Episodes (JSON):**
```bash
# Already in portable JSON format
cat data/episodes/episode_0001.json
```

**Patterns (SQLite → JSON):**
```python
from src.knowledge.graph import SecurityKnowledgeGraph

kg = SecurityKnowledgeGraph()
patterns = kg.get_all_patterns()

import json
with open('patterns_export.json', 'w') as f:
    json.dump([p.to_dict() for p in patterns], f, indent=2)
```

**Audit Logs (JSONL):**
```bash
# Already in line-delimited JSON
cat data/audit/audit.log | jq .
```

### Import to Other Systems

All data is stored in standard formats (JSON, SQLite) for easy integration:
- JSON episodes → Any analysis tool
- SQLite patterns → Pandas, R, SQL tools
- Audit logs → SIEM systems, log analyzers

## Compliance

### Applicable Regulations

**GDPR:** Not applicable (no PII processing by design)
- Exception: User-provided code MAY contain PII (user's responsibility)

**CCPA:** Compliance status (if collecting California data):
- ✅ No sale of data
- ✅ Disclosure of categories collected
- ✅ Right to deletion supported

**HIPAA:** Not applicable (no health data)

**SOC 2:** In progress (15% ready)
- See SECURITY.md for roadmap

### Compliance Gaps

See `.claude/reports/compliance-review.md` for full analysis:
- ⚠️ Missing data classification system
- ⚠️ No encryption at rest
- ⚠️ No access controls
- ⚠️ No data loss prevention (DLP)

**Timeline:** 9-12 months to audit readiness

## Contact

**Data Protection Officer:** [TO BE CONFIGURED]

**Privacy Questions:** [TO BE CONFIGURED]

**Data Requests:** [TO BE CONFIGURED]

## Changes to This Policy

We will notify users of material changes via:
- GitHub release notes
- CHANGELOG.md updates
- Email (if we have contact info)

**Review Frequency:** Quarterly

**Last Review:** 2025-01-16

**Next Review:** 2025-04-16

---

**By using ASDS Self-Play, you acknowledge that you have read and understood this Data Policy.**
