# ASDS Self-Play Specialized Agents

This project uses three specialized AI agents that automatically provide expertise:

## 🎮 Game Theory Agent

**Role:** Strategic Analysis Expert

**Expertise:**
- Nash equilibrium analysis
- Mechanism design
- Incentive structures
- Multi-agent dynamics
- Evolutionary game theory
- Security games

**Responsibilities:**
- Analyze defender vs attacker game dynamics
- Evaluate reward function design
- Identify exploitable strategies
- Suggest mechanism improvements
- Predict strategic behavior
- Design experiments to test equilibria

**Triggers:**
The agent activates when you mention: reward, strategy, equilibrium, game, incentive, payoff

**Example Invocations:**
- "Analyze the reward function for game-theoretic issues"
- "What's the Nash equilibrium of the current system?"
- "Are there dominant strategies we should worry about?"
- "How can we improve incentive alignment?"

## 📋 Compliance Agent

**Role:** Documentation and Audit Expert

**Expertise:**
- SOC 2 compliance
- ISO 27001 controls
- GDPR requirements
- Audit trail management
- Evidence collection
- Chain of custody

**Responsibilities:**
- Ensure proper documentation
- Maintain audit trails
- Verify regulatory compliance
- Manage evidence packages
- Track data lineage
- Assess documentation gaps

**Triggers:**
The agent activates when you mention: commit, documentation, audit, compliance, evidence, regulatory

**Example Invocations:**
- "Review this commit for compliance"
- "What documentation is missing for audit?"
- "Ensure proper audit trail for findings"
- "Check regulatory compliance requirements"

## 🔬 Research Agent

**Role:** Security Research Specialist

**Expertise:**
- Academic paper search
- CVE and vulnerability databases
- Security tools and frameworks
- Dataset discovery
- Hypothesis validation
- Competitive analysis

**Responsibilities:**
- Search for relevant research papers
- Find security datasets and benchmarks
- Discover new vulnerability patterns
- Validate hypotheses with evidence
- Identify similar projects/tools
- Stay current on emerging threats

**Triggers:**
The agent activates when you mention: research, paper, benchmark, dataset, hypothesis, validate, prior art

**Example Invocations:**
- "Research papers on self-play security testing"
- "Find datasets for vulnerability detection"
- "What's the prior art in this area?"
- "Validate our hypothesis about in-context learning"

## How Agents Work

### Automatic Invocation

Agents are automatically invoked via hooks when you:
1. Submit prompts with trigger keywords
2. Commit code changes
3. Work on major features
4. Discuss strategic decisions

### Collaboration

Agents can work together:
- **Game Theory** + **Compliance**: Ensure reward mechanisms are auditable
- **Research** + **Game Theory**: Validate strategic designs with academic evidence
- **Research** + **Compliance**: Find industry standards and best practices

### Manual Invocation

You can explicitly request agent analysis:

```
@game-theory Analyze the current reward function design

@compliance Review our documentation for SOC 2 readiness

@research Find benchmarks for vulnerability detection accuracy
```

## Agent Outputs

Each agent provides structured analysis:

### Game Theory Agent Output
```markdown
## Game-Theoretic Analysis
- Nash Equilibria: [analysis]
- Incentive Alignment: [assessment]
- Strategic Risks: [identification]
- Recommendations: [improvements]
```

### Compliance Agent Output
```markdown
## Compliance Review
- Documentation Status: [checklist]
- Audit Trail Assessment: [rating]
- Regulatory Compliance: [gaps]
- Required Actions: [tasks]
```

### Research Agent Output
```markdown
## Research Findings
- Relevant Papers: [summaries]
- Similar Projects: [comparisons]
- Datasets/Benchmarks: [resources]
- Recommendations: [next steps]
```

## Configuration

Agents are configured in `.claude/claude.json`:

```json
{
  "agents": {
    "game-theory": { ... },
    "compliance": { ... },
    "research": { ... }
  },
  "skills": [ ... ],
  "hooks": { ... }
}
```

## Skills

Each agent has access to specialized skills:
- `game-theory-analysis.md` - Game theory expertise
- `compliance-documentation.md` - Compliance requirements
- `security-research.md` - Research methodology

## Example Workflow

1. **You:** "Let's improve the reward function"
   - 🎮 Game Theory Agent analyzes strategic implications
   - 📋 Compliance Agent ensures changes are documented

2. **You:** "Research similar self-play security systems"
   - 🔬 Research Agent searches papers and projects
   - 🎮 Game Theory Agent compares strategic approaches
   - 📋 Compliance Agent checks if prior art requires attribution

3. **You:** "Commit these changes"
   - 📋 Compliance Agent reviews documentation
   - 🔬 Research Agent validates against best practices
   - 🎮 Game Theory Agent checks for unintended strategic effects

## Benefits

✅ **Comprehensive Analysis** - Multiple expert perspectives on every decision
✅ **Automated Expertise** - Don't have to remember to check game theory or compliance
✅ **Evidence-Based** - Research agent provides academic backing
✅ **Audit-Ready** - Compliance agent ensures trail is maintained
✅ **Strategic Validation** - Game theory agent prevents exploitable designs

## Maintenance

To update agents:
1. Edit skill files in `.claude/skills/`
2. Modify triggers in `.claude/claude.json`
3. Update hooks in `.claude/hooks/`

Agents evolve with the project and learn from interactions.
