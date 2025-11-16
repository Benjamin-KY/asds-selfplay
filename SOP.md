# Standard Operating Procedures (SOP)

## Document Information

**Document Title:** ASDS Self-Play Standard Operating Procedures

**Version:** 1.0

**Effective Date:** 2025-01-16

**Review Date:** 2025-04-16 (Quarterly)

**Owner:** [TO BE ASSIGNED]

**Approver:** [TO BE ASSIGNED]

---

## Table of Contents

1. [System Setup](#1-system-setup)
2. [Training Operations](#2-training-operations)
3. [Security Operations](#3-security-operations)
4. [Incident Response](#4-incident-response)
5. [Maintenance](#5-maintenance)
6. [Backup and Recovery](#6-backup-and-recovery)
7. [Change Management](#7-change-management)
8. [Audit Operations](#8-audit-operations)

---

## 1. System Setup

### 1.1 Initial Installation

**Purpose:** Install and configure ASDS Self-Play for the first time

**Frequency:** One-time per environment

**Responsible:** System Administrator

**Procedure:**

1. **Prerequisites Check**
   ```bash
   # Verify Python version
   python --version  # Must be 3.10+

   # Verify Git installed
   git --version

   # Check available disk space
   df -h  # Need at least 10GB free
   ```

2. **Clone Repository**
   ```bash
   git clone https://github.com/[org]/asds-selfplay.git
   cd asds-selfplay
   ```

3. **Create Virtual Environment**
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

4. **Install Dependencies**
   ```bash
   pip install --upgrade pip
   pip install -r requirements.txt
   ```

5. **Set Environment Variables**
   ```bash
   # Create .env file
   cat > .env << EOF
   ANTHROPIC_API_KEY=your-api-key-here
   ASDS_AUDIT_SECRET_KEY=$(openssl rand -hex 32)
   EOF

   # Load environment
   source .env
   ```

6. **Verify Installation**
   ```bash
   # Test configuration loading
   python -m src.utils.config

   # Run test suite
   pytest tests/ -v
   ```

**Expected Outcome:** All tests pass, configuration loads successfully

**Rollback:** Delete directory and restart from step 1

### 1.2 Configuration

**Purpose:** Configure system for specific use case

**Frequency:** One-time per environment

**Procedure:**

1. **Review Default Configuration**
   ```bash
   cat config.yaml
   ```

2. **Customize Settings**
   ```yaml
   # Edit config.yaml
   model:
     name: "claude-sonnet-4-5-20250929"  # Or your preferred model
     temperature:
       analysis: 0.1  # Adjust as needed

   rewards:
     true_positive: 15.0  # Game theory optimized
     # ... (keep default values unless specific requirements)

   training:
     episodes_dir: "data/episodes"  # Change if needed
   ```

3. **Create Data Directories**
   ```bash
   mkdir -p data/{episodes,patterns,audit,checkpoints}
   mkdir -p logs
   ```

4. **Initialize Pattern Library (Optional)**
   ```python
   from src.patterns.library import initialize_pattern_library
   from src.knowledge.graph import SecurityKnowledgeGraph

   kg = SecurityKnowledgeGraph()
   initialize_pattern_library(kg)
   kg.save()
   ```

**Expected Outcome:** Configuration valid, directories created

---

## 2. Training Operations

### 2.1 Running Self-Play Training

**Purpose:** Train defender agent via adversarial self-play

**Frequency:** As needed (daily for active development)

**Responsible:** ML Engineer / Security Researcher

**Procedure:**

1. **Prepare Training Data**
   ```bash
   # Ensure vulnerable code samples exist
   ls vulnerable_code/

   # Or use built-in examples
   python -m src.data.examples
   ```

2. **Start Training Session**
   ```bash
   # Basic training (10 episodes)
   python src/train.py --episodes 10

   # Advanced training with custom dataset
   python src/train.py \
     --episodes 100 \
     --dataset vulnerable_code/ \
     --checkpoint-freq 10 \
     --save-traces
   ```

3. **Monitor Progress**
   ```bash
   # Watch logs in real-time
   tail -f logs/asds_selfplay.log

   # Check episode files
   ls -lh data/episodes/

   # Verify audit chain
   python -c "from src.utils.audit import TamperEvidentLogger; \
              logger = TamperEvidentLogger(); \
              print('Chain valid:', logger.verify_chain())"
   ```

4. **Review Results**
   ```python
   # Load and analyze episode
   import json
   with open('data/episodes/episode_0001.json') as f:
       episode = json.load(f)
       print(f"Reward: {episode['reward']}")
       print(f"TP/FP/FN: {episode['true_positives']}/{episode['false_positives']}/{episode['false_negatives']}")
   ```

**Expected Outcome:**
- Episodes saved to data/episodes/
- Audit log entries created
- Reward trends upward over time
- Pattern library grows

**Troubleshooting:**
- **API Errors:** Check ANTHROPIC_API_KEY
- **Low Rewards:** Review code samples quality
- **Chain Verification Failure:** Check audit.log for tampering

### 2.2 Evaluating Performance

**Purpose:** Assess defender performance metrics

**Frequency:** After every 10-100 episodes

**Procedure:**

1. **Generate Metrics Dashboard**
   ```bash
   python src/dashboard.py
   ```

2. **Calculate Aggregate Metrics**
   ```python
   from src.core.self_play import SelfPlayTrainer
   from src.knowledge.graph import SecurityKnowledgeGraph
   from src.agents.defender import DefenderAgent
   from src.agents.attacker import AttackerAgent

   kg = SecurityKnowledgeGraph()
   defender = DefenderAgent(kg)
   attacker = AttackerAgent()
   trainer = SelfPlayTrainer(kg, defender, attacker)

   progress = trainer.get_learning_progress()
   print(f"Total episodes: {progress['total_episodes']}")
   print(f"Reward improvement: {progress['improvement_pct']:.1f}%")
   ```

3. **Review Pattern Effectiveness**
   ```python
   kg = SecurityKnowledgeGraph()
   stats = kg.get_stats()

   print(f"Total patterns: {stats['total_patterns']}")
   print(f"Effective patterns (F1 > 0.7): {stats['effective_count']}")

   # Get top patterns
   patterns = sorted(kg.get_all_patterns(),
                    key=lambda p: p.f1_score,
                    reverse=True)[:10]
   for p in patterns:
       print(f"  {p.id}: F1={p.f1_score:.2f}, Brier={p.brier_score:.3f}")
   ```

**Success Criteria:**
- Reward increasing trend
- F1 score > 0.6 for top patterns
- Brier score < 0.3 (well-calibrated)
- TP rate > FP rate

---

## 3. Security Operations

### 3.1 Audit Log Verification

**Purpose:** Verify integrity of audit trail

**Frequency:** Daily (automated), Weekly (manual review)

**Responsible:** Security Administrator

**Procedure:**

1. **Automated Verification (Daily Cron)**
   ```bash
   # Add to crontab
   0 2 * * * cd /path/to/asds-selfplay && python -c "from src.utils.audit import TamperEvidentLogger; logger = TamperEvidentLogger(); logger.verify_chain()" || echo "ALERT: Audit chain verification failed!" | mail -s "ASDS Audit Alert" security@example.com
   ```

2. **Manual Verification**
   ```python
   from src.utils.audit import TamperEvidentLogger

   logger = TamperEvidentLogger()

   try:
       logger.verify_chain()
       print("✓ Audit chain intact")
   except ValueError as e:
       print(f"✗ TAMPERING DETECTED: {e}")
       # Escalate to security team
   ```

3. **Review Audit Statistics**
   ```python
   stats = logger.get_audit_stats()
   print(f"Total entries: {stats['total_entries']}")
   print(f"Date range: {stats['first_timestamp']} to {stats['last_timestamp']}")
   print(f"Chain valid: {stats['chain_valid']}")
   ```

**Alert Conditions:**
- Chain verification fails
- Missing audit entries
- Timestamp anomalies
- Unexpected signature patterns

### 3.2 Secret Rotation

**Purpose:** Rotate audit secret key periodically

**Frequency:** Quarterly

**Responsible:** Security Administrator

**Procedure:**

**⚠️ WARNING:** This breaks the audit chain. Only perform during scheduled maintenance.

1. **Backup Current Audit Log**
   ```bash
   cp data/audit/audit.log data/audit/audit.log.$(date +%Y%m%d).bak
   ```

2. **Generate New Secret**
   ```bash
   NEW_SECRET=$(openssl rand -hex 32)
   echo "New secret: $NEW_SECRET"  # Store securely in vault
   ```

3. **Update Environment**
   ```bash
   # Update .env file
   sed -i "s/ASDS_AUDIT_SECRET_KEY=.*/ASDS_AUDIT_SECRET_KEY=$NEW_SECRET/" .env

   # Reload environment
   source .env
   ```

4. **Archive Old Log**
   ```bash
   # Move old log to archive
   mv data/audit/audit.log data/audit/audit.log.archived.$(date +%Y%m%d)

   # Create new empty log
   touch data/audit/audit.log
   ```

5. **Document Rotation**
   ```bash
   echo "$(date): Secret rotated. Old log archived." >> data/audit/rotation_log.txt
   ```

**Post-Rotation:**
- Verify new secret works
- Test audit logging
- Update runbooks with new secret location

---

## 4. Incident Response

### 4.1 Security Incident Detection

**Purpose:** Detect and respond to security incidents

**Frequency:** Continuous monitoring

**Responsible:** Security Team

**Trigger Events:**
- Audit chain verification failure
- Unusual API usage patterns
- Unexpected file modifications
- Access control violations (when implemented)

**Procedure:**

1. **Incident Classification**
   - **P0 (Critical):** Audit chain compromise, data breach
   - **P1 (High):** Unauthorized access attempt
   - **P2 (Medium):** Dependency vulnerability
   - **P3 (Low):** Configuration drift

2. **Immediate Response (P0/P1)**
   ```bash
   # Stop all training
   pkill -f "python src/train.py"

   # Isolate system (if networked)
   sudo iptables -A INPUT -j DROP
   sudo iptables -A OUTPUT -j DROP

   # Create incident snapshot
   tar -czf incident_$(date +%Y%m%d_%H%M%S).tar.gz \
     data/ logs/ config.yaml .env
   ```

3. **Evidence Collection**
   ```bash
   # Collect system info
   uname -a > incident_system_info.txt
   ps aux >> incident_system_info.txt
   netstat -tulpn >> incident_system_info.txt

   # Collect logs
   cp -r logs/ incident_logs/
   cp data/audit/audit.log incident_audit.log

   # Calculate file hashes
   find data/ -type f -exec sha256sum {} \; > incident_hashes.txt
   ```

4. **Root Cause Analysis**
   - Review audit logs for anomalies
   - Check git history for unauthorized changes
   - Verify audit chain integrity
   - Review API usage logs

5. **Containment & Eradication**
   - Restore from known-good backup
   - Rotate all secrets
   - Patch vulnerabilities
   - Update access controls

6. **Recovery**
   - Verify system integrity
   - Restart services
   - Monitor for 72 hours
   - Document lessons learned

**Escalation:**
- P0: Immediate notification to Security Lead + Management
- P1: Notification within 1 hour
- P2: Notification within 24 hours
- P3: Weekly summary

### 4.2 Data Breach Response

**Purpose:** Respond to suspected data exposure

**Frequency:** As needed

**Trigger:** Suspected unauthorized access to sensitive data

**Procedure:**

1. **Assess Scope**
   ```bash
   # Check for suspicious file access
   find data/ -type f -mtime -7  # Files modified in last 7 days

   # Review audit log for unusual patterns
   grep -i "suspicious_pattern" data/audit/audit.log
   ```

2. **Identify Affected Data**
   - Episode data (code samples, findings)
   - Pattern library (proprietary knowledge)
   - Configuration (may contain secrets)
   - Audit logs (compliance evidence)

3. **Notification (if required)**
   - Determine if PII was exposed
   - Notify affected parties within 72 hours (GDPR)
   - Report to regulatory bodies if required

4. **Remediation**
   - Revoke compromised credentials
   - Delete exposed data if necessary
   - Implement additional access controls
   - Update security procedures

---

## 5. Maintenance

### 5.1 Dependency Updates

**Purpose:** Keep dependencies up-to-date and secure

**Frequency:** Monthly (security patches immediately)

**Responsible:** Development Team

**Procedure:**

1. **Check for Updates**
   ```bash
   pip list --outdated
   ```

2. **Security Scan**
   ```bash
   pip install pip-audit
   pip-audit
   ```

3. **Update Dependencies**
   ```bash
   # Create backup
   cp requirements.txt requirements.txt.bak

   # Update (test environment first!)
   pip install --upgrade -r requirements.txt
   pip freeze > requirements.txt
   ```

4. **Testing**
   ```bash
   # Run full test suite
   pytest tests/ -v

   # Verify training still works
   python src/train.py --episodes 1
   ```

5. **Rollback (if needed)**
   ```bash
   pip install -r requirements.txt.bak
   ```

**Approval Required:** Yes (for production)

### 5.2 Pattern Library Maintenance

**Purpose:** Prune ineffective patterns and add new ones

**Frequency:** Monthly

**Procedure:**

1. **Review Pattern Statistics**
   ```python
   from src.knowledge.graph import SecurityKnowledgeGraph

   kg = SecurityKnowledgeGraph()
   stats = kg.get_stats()

   # Identify ineffective patterns
   patterns = kg.get_all_patterns()
   ineffective = [p for p in patterns
                  if p.observations >= 20 and p.effectiveness < 0.3]

   print(f"Ineffective patterns: {len(ineffective)}")
   for p in ineffective:
       print(f"  {p.id}: effectiveness={p.effectiveness:.2f}")
   ```

2. **Prune Ineffective Patterns**
   ```python
   kg.prune_ineffective_patterns(
       min_observations=20,
       effectiveness_threshold=0.3
   )
   kg.save()
   ```

3. **Add New Patterns (if available)**
   ```python
   from src.knowledge.graph import SecurityPattern, PatternType

   new_pattern = SecurityPattern(
       id="PATTERN-NEW-001",
       name="New Vulnerability Type",
       pattern_type=PatternType.SQL_INJECTION,
       code_example='...', language="python",
       risk_level="high",
       cwe_id="CWE-XXX"
   )

   kg.add_pattern(new_pattern)
   kg.save()
   ```

---

## 6. Backup and Recovery

### 6.1 Regular Backups

**Purpose:** Protect against data loss

**Frequency:** Daily (automated)

**Responsible:** System Administrator

**Procedure:**

1. **Automated Backup Script**
   ```bash
   #!/bin/bash
   # /etc/cron.daily/asds-backup

   BACKUP_DIR="/backups/asds"
   DATE=$(date +%Y%m%d)

   cd /path/to/asds-selfplay

   # Create backup
   tar -czf "$BACKUP_DIR/asds_backup_$DATE.tar.gz" \
     data/patterns/ \
     data/audit/ \
     config.yaml \
     .env

   # Keep only last 30 days
   find "$BACKUP_DIR" -name "asds_backup_*.tar.gz" -mtime +30 -delete

   # Verify backup
   tar -tzf "$BACKUP_DIR/asds_backup_$DATE.tar.gz" > /dev/null || \
     echo "Backup verification failed!" | mail -s "ASDS Backup Alert" admin@example.com
   ```

2. **Off-site Replication (Optional)**
   ```bash
   # Upload to cloud storage
   aws s3 cp "$BACKUP_DIR/asds_backup_$DATE.tar.gz" \
     s3://your-bucket/asds-backups/
   ```

**Backup Retention:**
- Daily backups: 30 days
- Weekly backups: 3 months
- Monthly backups: 1 year
- Yearly backups: Indefinite

### 6.2 Disaster Recovery

**Purpose:** Restore system after catastrophic failure

**Frequency:** As needed

**RTO (Recovery Time Objective):** 4 hours

**RPO (Recovery Point Objective):** 24 hours

**Procedure:**

1. **Assess Damage**
   - Identify what was lost
   - Determine most recent valid backup
   - Check backup integrity

2. **Restore from Backup**
   ```bash
   # Stop services
   pkill -f "python src/train.py"

   # Extract backup
   tar -xzf /backups/asds/asds_backup_20250116.tar.gz

   # Verify extraction
   ls -lR data/
   ```

3. **Verify Integrity**
   ```bash
   # Verify audit chain
   python -c "from src.utils.audit import TamperEvidentLogger; \
              logger = TamperEvidentLogger(); \
              logger.verify_chain()"

   # Test configuration
   python -m src.utils.config
   ```

4. **Restart Services**
   ```bash
   # Run health check
   pytest tests/ -v

   # Test training
   python src/train.py --episodes 1
   ```

5. **Document Recovery**
   ```bash
   echo "$(date): System restored from backup $(basename $BACKUP_FILE)" >> recovery_log.txt
   ```

---

## 7. Change Management

### 7.1 Configuration Changes

**Purpose:** Manage changes to system configuration

**Frequency:** As needed

**Responsible:** Development Team

**Approval Required:** Yes (for production)

**Procedure:**

1. **Create Change Request**
   ```
   Change ID: CR-2025-001
   Requestor: [Name]
   Date: [Date]
   Type: Configuration Change
   Description: Update reward weights
   Justification: Game theory optimization
   Impact: Medium (affects training rewards)
   Rollback Plan: Restore previous config.yaml
   ```

2. **Test Change (Development Environment)**
   ```bash
   # Edit config.yaml
   vim config.yaml

   # Test with 10 episodes
   python src/train.py --episodes 10

   # Compare metrics
   python -c "from src.core.self_play import SelfPlayTrainer; ..."
   ```

3. **Code Review**
   ```bash
   git add config.yaml
   git commit -m "config: Update reward weights (CR-2025-001)"
   git push origin feature/CR-2025-001

   # Create pull request
   gh pr create --title "CR-2025-001: Update reward weights"
   ```

4. **Approval & Deployment**
   - Technical review: Development Lead
   - Security review: Security Team (if security-related)
   - Final approval: System Owner

   ```bash
   # Merge to main
   git checkout main
   git merge feature/CR-2025-001
   git push origin main
   ```

5. **Post-Deployment Verification**
   ```bash
   # Verify configuration loaded
   python -m src.utils.config

   # Monitor first 10 episodes
   python src/train.py --episodes 10
   ```

### 7.2 Code Changes

**Purpose:** Manage changes to source code

**Procedure:**

1. **Development**
   - Create feature branch
   - Implement changes
   - Write tests
   - Update documentation

2. **Testing**
   ```bash
   pytest tests/ -v --cov=src/
   ```

3. **Code Review**
   - Submit pull request
   - Address review comments
   - Re-test after changes

4. **Merge & Deploy**
   - Squash commits if needed
   - Merge to main
   - Tag release if significant

---

## 8. Audit Operations

### 8.1 Monthly Audit

**Purpose:** Verify compliance and security controls

**Frequency:** Monthly

**Responsible:** Compliance Officer

**Procedure:**

1. **Audit Log Review**
   ```python
   from src.utils.audit import TamperEvidentLogger

   logger = TamperEvidentLogger()
   stats = logger.get_audit_stats()

   # Check for gaps
   # Check for anomalies
   # Verify chain integrity
   ```

2. **Configuration Review**
   ```bash
   # Verify no unauthorized changes
   git log --since="1 month ago" config.yaml

   # Check for secrets in config
   grep -i "password\|secret\|key" config.yaml
   ```

3. **Access Review**
   - Review file permissions
   - Check API key usage
   - Verify authentication logs (when implemented)

4. **Evidence Collection**
   - Export audit logs
   - Screenshot dashboards
   - Document findings

5. **Report**
   ```
   Monthly Audit Report - January 2025

   Summary:
   - Episodes processed: 500
   - Audit chain: Intact ✓
   - Configuration: No unauthorized changes ✓
   - Vulnerabilities: 0 critical, 2 medium
   - Compliance score: 35%

   Findings:
   1. [Finding description]
   2. [Finding description]

   Recommendations:
   1. [Recommendation]
   2. [Recommendation]
   ```

**Deliverables:**
- Monthly audit report
- Evidence archive
- Corrective action plan (if needed)

---

## Appendix A: Contact Information

**System Owner:** [Name, Email, Phone]

**Security Lead:** [Name, Email, Phone]

**Compliance Officer:** [Name, Email, Phone]

**On-Call Rotation:** [Schedule/Contact]

**Escalation:**
- P0: Security Lead + Management (immediate)
- P1: Security Lead (1 hour)
- P2: System Owner (24 hours)
- P3: Weekly summary

---

## Appendix B: Runbook Quick Reference

### Emergency Commands

```bash
# Stop all training
pkill -f "python src/train.py"

# Verify audit integrity
python -c "from src.utils.audit import TamperEvidentLogger; logger = TamperEvidentLogger(); logger.verify_chain()"

# Create emergency backup
tar -czf emergency_backup_$(date +%Y%m%d_%H%M%S).tar.gz data/ logs/ config.yaml

# Check system health
pytest tests/ -v

# Review recent logs
tail -100 logs/asds_selfplay.log
```

---

## Document History

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.0 | 2025-01-16 | [Author] | Initial version |

---

**END OF DOCUMENT**
