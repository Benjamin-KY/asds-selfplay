# Security Policy

## Overview

ASDS Self-Play is a security research system that uses adversarial self-play and reinforcement learning to detect vulnerabilities. As a security tool, we take the security of the system itself seriously.

**Current Status:** Development/Research (NOT production-ready)

**Security Maturity:** 25% (Development Stage)
- See `.claude/reports/compliance-review.md` for full assessment
- Target: 80%+ for production use

## Reporting Security Vulnerabilities

### Responsible Disclosure

If you discover a security vulnerability in ASDS Self-Play, please report it responsibly:

**Email:** [Your security contact email - TO BE CONFIGURED]

**PGP Key:** [Your PGP key fingerprint - TO BE CONFIGURED]

**Please include:**
- Description of the vulnerability
- Steps to reproduce
- Potential impact assessment
- Suggested remediation (if any)

**Response Timeline:**
- Initial response: Within 48 hours
- Status update: Within 7 days
- Resolution target: Within 30 days (critical), 90 days (others)

### What to Report

Please report any of the following:

- **Code Execution:** Arbitrary code execution vulnerabilities
- **Injection Attacks:** SQL injection, command injection, prompt injection
- **Authentication Bypass:** Unauthorized access to data or functionality
- **Data Leakage:** Unintended exposure of sensitive data
- **Cryptographic Weaknesses:** Flaws in audit logging or signatures
- **Supply Chain Issues:** Vulnerable dependencies

### Out of Scope

The following are not considered security vulnerabilities:

- Issues in example/demo code clearly marked as such
- Vulnerabilities requiring physical access to the machine
- Social engineering attacks
- Issues already documented in known limitations

## Security Controls Implemented

### ✅ Cryptographic Audit Logging

**Status:** Implemented (v2.0)

- **SHA-256** hashing of all episode data
- **HMAC-SHA256** signatures with secret key
- **Hash chain** linking episodes for tamper detection
- **Append-only** audit log semantics

**Configuration:**
```bash
export ASDS_AUDIT_SECRET_KEY="your-32-byte-hex-secret"
```

**Verification:**
```python
from src.utils.audit import TamperEvidentLogger

logger = TamperEvidentLogger()
logger.verify_chain()  # Raises ValueError if tampered
```

### ✅ Game Theory Hardened Rewards

**Status:** Implemented (v2.0)

- Balanced reward weights to prevent gaming
- Calibration bonuses for honest uncertainty
- Exploration incentives for pattern diversity
- Attacker reward function for adversarial pressure

See `config.yaml` for current reward parameters.

### ⚠️ Authentication & Access Controls

**Status:** NOT IMPLEMENTED (Planned for v2.1)

**Current Risk:** Anyone with filesystem access can:
- Read training data
- Modify configurations
- Access audit logs

**Planned Controls:**
- API key authentication for remote access
- Role-based access control (RBAC)
- File permission hardening
- Secure credential storage

### ⚠️ Data Encryption

**Status:** NOT IMPLEMENTED (Planned for v2.1)

**Current Risk:**
- Episode data stored in plaintext
- Database files unencrypted
- Sensitive patterns visible on disk

**Planned Controls:**
- Encryption at rest (AES-256)
- Encrypted database connections
- Secure key management via KMS

### ⚠️ Input Validation & Sandboxing

**Status:** PARTIAL (LLM-based validation only)

**Current Risk:**
- Code samples processed without sandboxing
- Potential for malicious code analysis
- No resource limits on analysis

**Planned Controls:**
- Sandboxed execution environment
- Resource limits (CPU, memory, time)
- Input sanitization and validation
- Code signing for trusted samples

## Threat Model

### Assets to Protect

1. **Training Data:** Vulnerability patterns and code samples
2. **Audit Logs:** Episode history and signatures
3. **Model Knowledge:** Learned security patterns
4. **API Credentials:** LLM provider keys

### Threat Actors

1. **Malicious Users:** Attempting to poison training data
2. **Attackers:** Seeking to extract proprietary patterns
3. **Insiders:** With filesystem access
4. **Supply Chain:** Compromised dependencies

### Attack Vectors

| Vector | Risk Level | Mitigation Status |
|--------|-----------|-------------------|
| Malicious code samples | HIGH | ⚠️ Partial (LLM validation) |
| Training data poisoning | HIGH | ⚠️ Partial (audit logging) |
| Audit log tampering | MEDIUM | ✅ Mitigated (signatures) |
| Pattern extraction | MEDIUM | ❌ Not mitigated |
| Credential theft | HIGH | ⚠️ Partial (env vars) |
| Dependency vulnerabilities | MEDIUM | ⚠️ Partial (requirements.txt) |

## Security Best Practices

### For Researchers

**✅ DO:**
- Use separate API keys for dev/prod
- Store `ASDS_AUDIT_SECRET_KEY` in secure vault
- Run in isolated environment (Docker, VM)
- Regularly verify audit chain integrity
- Review dependency vulnerabilities with `pip-audit`
- Use the latest version from main branch

**❌ DON'T:**
- Commit API keys or secrets to git
- Run on untrusted code samples without sandboxing
- Share audit logs containing sensitive data
- Disable security features in production
- Trust findings without attacker validation

### For Production Deployments

**⚠️ WARNING:** ASDS Self-Play is currently in DEVELOPMENT status.

**NOT RECOMMENDED for production use** until:
- [ ] Authentication & access controls implemented
- [ ] Encryption at rest enabled
- [ ] Input validation & sandboxing complete
- [ ] Security audit passed
- [ ] Compliance certifications obtained

**If you must deploy:**
1. Run in fully isolated network segment
2. Enable all available security features
3. Implement additional access controls
4. Monitor audit logs continuously
5. Set up automated alerting
6. Maintain offline backups

## Data Security

### Data Classification

| Data Type | Sensitivity | Encryption | Retention |
|-----------|-------------|------------|-----------|
| Code samples | HIGH | ⚠️ Planned | 90 days default |
| Vulnerability findings | CRITICAL | ⚠️ Planned | Indefinite |
| Audit logs | MEDIUM | ✅ Signed | Indefinite |
| Pattern library | HIGH | ⚠️ Planned | Indefinite |
| LLM prompts/responses | HIGH | ❌ None | Episode lifetime |
| Configuration | MEDIUM | ❌ None | Indefinite |

### Data Retention

**Default Policies:**
- **Episodes:** 90 days (configurable)
- **Audit Logs:** Indefinite (compliance requirement)
- **Pattern Knowledge:** Indefinite
- **Temporary Files:** Deleted on exit

**Manual Cleanup:**
```bash
# Clear episode data (keeps audit log)
rm -rf data/episodes/*

# DANGER: Clear everything including audit trail
rm -rf data/
```

### Data Disposal

When decommissioning:
1. Export patterns to secure backup
2. Verify audit chain integrity
3. Archive audit logs to cold storage
4. Securely wipe episode data (e.g., `shred -u`)
5. Revoke all API credentials
6. Document disposal in change log

## Incident Response

### Detection

**Monitoring for:**
- Audit chain verification failures
- Unusual pattern of findings (possible poisoning)
- High false positive rates (gaming detection)
- Unauthorized file access
- Dependency CVEs

### Response Procedure

1. **Identify:** Confirm incident via logs/monitoring
2. **Contain:** Isolate affected systems
3. **Eradicate:** Remove malicious data/access
4. **Recover:** Restore from known-good backup
5. **Review:** Post-incident analysis

### Escalation

- **P0 (Critical):** Audit chain compromise → Immediate stop, restore from backup
- **P1 (High):** Data breach → Notify stakeholders within 24h
- **P2 (Medium):** Dependency CVE → Patch within 7 days
- **P3 (Low):** Minor bug → Fix in next release

## Compliance Status

### ISO 27001:2022

**Coverage:** ~20%

**Implemented:**
- A.8.16: Monitoring (partial - audit logging)
- A.8.9: Configuration management

**Gaps:**
- A.5: Information security policies
- A.6: Organization of information security
- A.7: Human resource security
- A.8: Asset management (partial)

See `.claude/reports/compliance-review.md` for full gap analysis.

### SOC 2 Type II

**Readiness:** ~15%

**Implemented:**
- CC6.1: Logical access (partial)
- CC7.2: System monitoring (partial)

**Gaps:**
- CC1: Control environment
- CC2: Communication
- CC5: Confidentiality
- CC6.7: Encryption

**Timeline to Audit:** 9-12 months

### GDPR Compliance

**Status:** Not applicable (no PII processed)

**However:**
- If analyzing production codebases: Review for PII in code comments
- If storing user data: Implement GDPR controls

## Security Roadmap

### v2.1 (Q1 2025) - Security Hardening

- [ ] Implement authentication & authorization
- [ ] Add encryption at rest (AES-256)
- [ ] Input validation & sandboxing
- [ ] Dependency scanning automation
- [ ] Security testing suite

### v2.2 (Q2 2025) - Compliance Ready

- [ ] Complete ISO 27001 implementation
- [ ] SOC 2 control documentation
- [ ] Third-party security audit
- [ ] Penetration testing
- [ ] Security certification

### v3.0 (Q3 2025) - Production Ready

- [ ] Zero-trust architecture
- [ ] Multi-tenancy support
- [ ] Secrets management integration
- [ ] SIEM integration
- [ ] Compliance automation

## Security Dependencies

### Critical Dependencies

Monitor these for CVEs:

- **anthropic** (LLM provider) - Credential security
- **networkx** (knowledge graph) - Potential for graph attacks
- **sqlite3** (database) - SQL injection risks
- **pyyaml** (config parsing) - Deserialization attacks

**Update Policy:**
- Security patches: Within 48 hours
- Minor updates: Monthly
- Major updates: Quarterly (with testing)

### Automated Scanning

```bash
# Check for known vulnerabilities
pip install pip-audit
pip-audit

# Update dependencies
pip install --upgrade -r requirements.txt
```

## Contact & Resources

**Security Team:** [TO BE CONFIGURED]

**Security Email:** [TO BE CONFIGURED]

**Bug Bounty:** Not currently available

**Resources:**
- [ARCHITECTURE.md](ARCHITECTURE.md) - System architecture
- [AGENT_ANALYSIS_TODO.md](AGENT_ANALYSIS_TODO.md) - Security roadmap
- `.claude/reports/compliance-review.md` - Compliance assessment

## Changelog

### v2.0 (2025-01)
- ✅ Implemented tamper-evident audit logging
- ✅ Added cryptographic signatures (HMAC-SHA256)
- ✅ Implemented hash chain for episodes
- ✅ Game theory hardened reward function

### v1.0 (2024)
- Initial research implementation
- Basic pattern learning
- No security controls

---

**Last Updated:** 2025-01-16

**Next Review:** 2025-02-16 (Monthly)
