"""
Dynamic Prompt Generator

Builds prompts with in-context learning from knowledge graph.
Prompts improve as patterns learn effectiveness.
"""

from typing import List, Dict, Optional
from src.knowledge.graph import SecurityKnowledgeGraph, SecurityPattern


class DynamicPromptGenerator:
    """
    Generates analysis prompts with learned patterns as few-shot examples.

    Key idea: Instead of fine-tuning the model, we dynamically build prompts
    that include effective patterns as positive examples and ineffective
    patterns as negative examples (what to avoid).
    """

    def __init__(self, knowledge_graph: SecurityKnowledgeGraph):
        self.kg = knowledge_graph

    def generate_analysis_prompt(
        self,
        code: str,
        language: str = "python",
        context: Optional[Dict] = None
    ) -> str:
        """
        Generate security analysis prompt with learned patterns.

        Args:
            code: Code to analyze
            language: Programming language
            context: Additional context (file type, framework, etc.)

        Returns:
            Prompt string with in-context learning examples
        """
        context = context or {}

        # Get learned patterns
        effective_patterns = self.kg.get_effective_patterns(
            min_effectiveness=0.7,
            language=language,
            limit=5
        )

        recent_patterns = self.kg.get_recent_patterns(limit=3)

        ineffective_patterns = self.kg.get_ineffective_patterns(
            max_effectiveness=0.3,
            min_observations=5
        )

        # Get stats for context
        stats = self.kg.get_stats()

        # Build prompt
        prompt = self._build_prompt_header(stats)
        prompt += self._build_effective_patterns_section(effective_patterns)
        prompt += self._build_recent_patterns_section(recent_patterns)
        prompt += self._build_ineffective_patterns_section(ineffective_patterns)
        prompt += self._build_code_section(code, language)
        prompt += self._build_instructions_section()
        prompt += self._build_output_format_section()

        return prompt

    def _build_prompt_header(self, stats: Dict) -> str:
        """Build prompt header with system context"""
        return f"""You are a security analyst with access to learned security patterns.

LEARNING CONTEXT:
- Total patterns analyzed: {stats['total_patterns']}
- Total code samples reviewed: {stats['total_observations']}
- Average pattern effectiveness: {stats['avg_effectiveness']:.1%}

Your analysis should prioritize patterns with proven track records and avoid
patterns known to produce false positives.

"""

    def _build_effective_patterns_section(
        self,
        patterns: List[SecurityPattern]
    ) -> str:
        """Build section showing high-value patterns"""
        if not patterns:
            return ""

        section = "✅ HIGH-VALUE PATTERNS (prioritize these):\n\n"
        section += "These patterns have consistently detected real vulnerabilities:\n\n"

        for i, pattern in enumerate(patterns, 1):
            section += f"{i}. **{pattern.name}** ({pattern.risk_level})\n"
            section += f"   Type: {pattern.pattern_type.value}\n"
            section += f"   CWE: {pattern.cwe_id}\n"
            section += f"   Effectiveness: {pattern.effectiveness:.1%} "
            section += f"(Precision: {pattern.precision:.1%}, Recall: {pattern.recall:.1%})\n"
            section += f"   Example:\n"
            section += f"   ```{pattern.language}\n"
            section += f"   {pattern.code_example}\n"
            section += f"   ```\n"
            section += f"   ⚠️ This pattern has detected {pattern.true_positives} real vulnerabilities.\n\n"

        return section

    def _build_recent_patterns_section(
        self,
        patterns: List[SecurityPattern]
    ) -> str:
        """Build section showing recently discovered patterns"""
        if not patterns:
            return ""

        section = "🆕 RECENTLY DISCOVERED PATTERNS:\n\n"
        section += "These patterns are new - validate carefully:\n\n"

        for i, pattern in enumerate(patterns, 1):
            section += f"{i}. **{pattern.name}** ({pattern.risk_level})\n"
            section += f"   Type: {pattern.pattern_type.value}\n"
            section += f"   Example:\n"
            section += f"   ```{pattern.language}\n"
            section += f"   {pattern.code_example}\n"
            section += f"   ```\n"
            section += f"   ℹ️ Limited data - {pattern.observations} observations so far.\n\n"

        return section

    def _build_ineffective_patterns_section(
        self,
        patterns: List[SecurityPattern]
    ) -> str:
        """Build section showing patterns to avoid"""
        if not patterns:
            return ""

        section = "❌ AVOID FALSE POSITIVES:\n\n"
        section += "These patterns historically produce many false alarms - be skeptical:\n\n"

        for i, pattern in enumerate(patterns, 1):
            section += f"{i}. **{pattern.name}**\n"
            section += f"   False positive rate: {(pattern.false_positives / pattern.observations * 100):.0f}%\n"
            section += f"   ({pattern.false_positives} false positives out of {pattern.observations} checks)\n"
            section += f"   Example (often flagged but rarely exploitable):\n"
            section += f"   ```{pattern.language}\n"
            section += f"   {pattern.code_example}\n"
            section += f"   ```\n"
            section += f"   ⚠️ Only flag this if you have high confidence.\n\n"

        return section

    def _build_code_section(self, code: str, language: str) -> str:
        """Build code analysis section"""
        return f"""CODE TO ANALYZE:

```{language}
{code}
```

"""

    def _build_instructions_section(self) -> str:
        """Build analysis instructions"""
        return """ANALYSIS TASK:

1. **Prioritize high-value patterns** - Check effective patterns first
2. **Consider recent discoveries** - Look for newly identified vulnerabilities
3. **Avoid false positive patterns** - Be skeptical of patterns with poor track records
4. **Provide confidence scores** - Rate your certainty (0.0 - 1.0)
5. **Explain your reasoning** - Why is this a vulnerability?

For each potential vulnerability:
- Identify the pattern type
- Specify CWE ID
- Assess severity (critical/high/medium/low)
- Provide specific code location
- Explain the security risk
- Suggest a specific fix
- Rate confidence (based on pattern effectiveness)

"""

    def _build_output_format_section(self) -> str:
        """Build output format specification"""
        return """OUTPUT FORMAT (JSON):

{
  "findings": [
    {
      "id": "unique-finding-id",
      "type": "SQL Injection",
      "pattern_id": "PATTERN-SQL-001",
      "cwe_id": "CWE-89",
      "severity": "critical",
      "location": "line 42",
      "code_snippet": "query = f\\"SELECT * FROM users WHERE id={user_id}\\"",
      "explanation": "User input directly concatenated into SQL query allows injection attacks",
      "suggested_fix": "Use parameterized queries: cursor.execute(\\"SELECT * FROM users WHERE id=?\\", (user_id,))",
      "confidence": 0.95
    }
  ],
  "patterns_checked": ["PATTERN-SQL-001", "PATTERN-XSS-001", ...],
  "overall_risk": "high"
}

Ensure all findings reference pattern_ids from the high-value patterns section when applicable.
"""

    def generate_fix_prompt(
        self,
        finding: Dict,
        original_code: str
    ) -> str:
        """
        Generate prompt for suggesting fixes.

        Args:
            finding: The vulnerability finding
            original_code: Original vulnerable code

        Returns:
            Prompt for fix generation
        """
        pattern_id = finding.get("pattern_id")
        pattern = self.kg.patterns.get(pattern_id) if pattern_id else None

        prompt = f"""You are a security expert fixing a vulnerability.

VULNERABILITY DETAILS:
- Type: {finding['type']}
- CWE: {finding.get('cwe_id', 'Unknown')}
- Severity: {finding['severity']}
- Location: {finding['location']}

VULNERABLE CODE:
```
{original_code}
```

EXPLANATION:
{finding['explanation']}

"""

        if pattern:
            prompt += f"""LEARNED MITIGATION CONTEXT:
This pattern ({pattern.name}) has been successfully fixed {pattern.true_positives} times before.
"""

        prompt += """TASK:
Generate a secure version of this code that:
1. Eliminates the vulnerability
2. Maintains the original functionality
3. Follows security best practices
4. Uses framework-specific security features when available

OUTPUT FORMAT:
{
  "fixed_code": "... secure version ...",
  "explanation": "Why this fix works",
  "verification_steps": ["How to test the fix"]
}
"""

        return prompt


class PromptOptimizer:
    """
    Optimizes prompt templates based on Agent Lightning feedback.

    This works with Agent Lightning's RL framework to improve
    prompt strategies over time.
    """

    def __init__(self, knowledge_graph: SecurityKnowledgeGraph):
        self.kg = knowledge_graph
        self.template_strategies = {
            "thorough": self._thorough_strategy,
            "fast": self._fast_strategy,
            "balanced": self._balanced_strategy
        }

    def _thorough_strategy(self, code: str, language: str) -> str:
        """Detailed analysis with all patterns"""
        generator = DynamicPromptGenerator(self.kg)
        # Override to include more patterns
        return generator.generate_analysis_prompt(code, language)

    def _fast_strategy(self, code: str, language: str) -> str:
        """Quick scan with only top patterns"""
        generator = DynamicPromptGenerator(self.kg)
        # Could modify to only include top 3 patterns
        return generator.generate_analysis_prompt(code, language)

    def _balanced_strategy(self, code: str, language: str) -> str:
        """Balanced approach"""
        generator = DynamicPromptGenerator(self.kg)
        return generator.generate_analysis_prompt(code, language)

    def select_strategy(self, context: Dict) -> str:
        """
        Select prompt strategy based on context.

        Agent Lightning will learn which strategies work best.
        """
        # For now, default to balanced
        # Agent Lightning will optimize this choice
        return "balanced"


if __name__ == "__main__":
    # Test prompt generation
    from src.knowledge.graph import SecurityKnowledgeGraph

    kg = SecurityKnowledgeGraph()

    # Simulate some learning
    kg.update_pattern_effectiveness("PATTERN-SQL-001", is_true_positive=True)
    kg.update_pattern_effectiveness("PATTERN-SQL-001", is_true_positive=True)
    kg.update_pattern_effectiveness("PATTERN-XSS-001", is_false_negative=False)

    generator = DynamicPromptGenerator(kg)

    sample_code = '''
def login(username, password):
    query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
    result = db.execute(query)
    return result
'''

    prompt = generator.generate_analysis_prompt(sample_code, "python")

    print("Generated Prompt:")
    print("=" * 80)
    print(prompt)
    print("=" * 80)
    print(f"\nPrompt length: {len(prompt)} characters")
