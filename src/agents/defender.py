"""
Defender Agent

Analyzes code for vulnerabilities using LLM + learned patterns.
Uses in-context learning via dynamic prompts.
"""

import json
import os
from typing import List, Dict, Optional, Any
from dataclasses import dataclass, asdict
from datetime import datetime
from anthropic import Anthropic

from src.knowledge.graph import SecurityKnowledgeGraph
from src.prompts.generator import DynamicPromptGenerator
from src.utils.config import get_config
from src.utils.logging_config import get_logger

logger = get_logger(__name__)


@dataclass
class Finding:
    """Security vulnerability finding"""
    id: str
    type: str
    pattern_id: Optional[str]
    cwe_id: Optional[str]
    severity: str  # critical, high, medium, low
    location: str
    code_snippet: str
    explanation: str
    suggested_fix: str
    confidence: float

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class DefenseTrace:
    """Trace of a defense analysis (for Agent Lightning)"""
    id: str
    code: str
    language: str
    prompt: str
    findings: List[Finding]
    patterns_checked: List[str]
    time_taken: float
    timestamp: datetime

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "code": self.code,
            "language": self.language,
            "prompt_length": len(self.prompt),
            "findings_count": len(self.findings),
            "findings": [f.to_dict() for f in self.findings],
            "patterns_checked": self.patterns_checked,
            "time_taken": self.time_taken,
            "timestamp": self.timestamp.isoformat()
        }


class DefenderAgent:
    """
    Security analysis agent that learns from experience.

    Uses:
    - Knowledge graph for pattern effectiveness
    - Dynamic prompts for in-context learning
    - LLM for actual analysis
    """

    def __init__(
        self,
        knowledge_graph: SecurityKnowledgeGraph,
        llm_client: Optional[Anthropic] = None,
        model: Optional[str] = None,
        rl_store: Optional[Any] = None  # LightningStore, imported dynamically to avoid circular deps
    ):
        self.kg = knowledge_graph
        self.prompt_generator = DynamicPromptGenerator(knowledge_graph)

        # Load config
        config = get_config()
        self.model = model or config.model.name
        self.temperature = config.model.temperature['analysis']
        self.max_tokens = config.model.max_tokens['analysis']

        # RL integration
        self.rl_store = rl_store
        self.current_trace_id: Optional[str] = None

        # Initialize LLM client
        if llm_client:
            self.llm = llm_client
        else:
            api_key = os.getenv("ANTHROPIC_API_KEY")
            if not api_key:
                raise ValueError("ANTHROPIC_API_KEY not set")
            self.llm = Anthropic(api_key=api_key)

        logger.info(f"DefenderAgent initialized with model={self.model}")

    def analyze(
        self,
        code: str,
        language: str = "python",
        context: Optional[Dict] = None
    ) -> DefenseTrace:
        """
        Analyze code for security vulnerabilities.

        Args:
            code: Code to analyze
            language: Programming language
            context: Additional context

        Returns:
            DefenseTrace with findings
        """
        start_time = datetime.now()

        # Emit trace start (if RL store available)
        if self.rl_store and self.current_trace_id:
            self.rl_store.emit_span(
                trace_id=self.current_trace_id,
                span_type="analysis_start",
                data={"code_length": len(code), "language": language}
            )

        # Generate dynamic prompt with learned patterns
        prompt = self.prompt_generator.generate_analysis_prompt(
            code=code,
            language=language,
            context=context
        )

        # Emit prompt span
        if self.rl_store and self.current_trace_id:
            self.rl_store.emit_span(
                trace_id=self.current_trace_id,
                span_type="prompt",
                data={"prompt": prompt[:500], "prompt_length": len(prompt)}  # Truncate for storage
            )

        # Call LLM for analysis
        try:
            response = self.llm.messages.create(
                model=self.model,
                max_tokens=self.max_tokens,
                temperature=self.temperature,
                messages=[{"role": "user", "content": prompt}]
            )

            response_text = response.content[0].text

            # Emit LLM response span
            if self.rl_store and self.current_trace_id:
                self.rl_store.emit_span(
                    trace_id=self.current_trace_id,
                    span_type="llm_response",
                    data={"response_length": len(response_text)}
                )

            # Parse findings from response
            findings, patterns_checked = self._parse_response(response_text)

            # Emit patterns checked span
            if self.rl_store and self.current_trace_id:
                self.rl_store.emit_span(
                    trace_id=self.current_trace_id,
                    span_type="patterns_checked",
                    data={"patterns": patterns_checked}
                )

        except Exception as e:
            logger.error(f"LLM error during analysis: {e}", exc_info=True)
            findings = []
            patterns_checked = []

        end_time = datetime.now()
        time_taken = (end_time - start_time).total_seconds()

        # Create trace
        trace = DefenseTrace(
            id=f"defense-{datetime.now().timestamp()}",
            code=code,
            language=language,
            prompt=prompt,
            findings=findings,
            patterns_checked=patterns_checked,
            time_taken=time_taken,
            timestamp=start_time
        )

        return trace

    def _parse_response(self, response_text: str) -> tuple[List[Finding], List[str]]:
        """
        Parse LLM response into structured findings.

        Args:
            response_text: Raw LLM response

        Returns:
            Tuple of (findings list, patterns_checked list)
        """
        findings = []
        patterns_checked = []

        try:
            # Try to extract JSON from response
            json_start = response_text.find('{')
            json_end = response_text.rfind('}') + 1

            if json_start >= 0 and json_end > json_start:
                json_str = response_text[json_start:json_end]
                data = json.loads(json_str)

                # Extract findings
                for f_data in data.get("findings", []):
                    finding = Finding(
                        id=f_data.get("id", f"finding-{len(findings)}"),
                        type=f_data.get("type", "Unknown"),
                        pattern_id=f_data.get("pattern_id"),
                        cwe_id=f_data.get("cwe_id"),
                        severity=f_data.get("severity", "medium"),
                        location=f_data.get("location", "unknown"),
                        code_snippet=f_data.get("code_snippet", ""),
                        explanation=f_data.get("explanation", ""),
                        suggested_fix=f_data.get("suggested_fix", ""),
                        confidence=f_data.get("confidence", 0.5)
                    )
                    findings.append(finding)

                # Extract patterns checked
                patterns_checked = data.get("patterns_checked", [])

        except json.JSONDecodeError as e:
            print(f"Failed to parse JSON response: {e}")
            # Fallback: try to extract findings from text
            # (Would need more sophisticated text parsing in production)

        return findings, patterns_checked

    def suggest_fixes(
        self,
        findings: List[Finding],
        original_code: str
    ) -> Dict[str, str]:
        """
        Generate fixes for identified vulnerabilities.

        Args:
            findings: List of vulnerabilities
            original_code: Original code

        Returns:
            Dict mapping finding IDs to fixed code
        """
        fixes = {}

        for finding in findings:
            # Generate fix prompt
            fix_prompt = self.prompt_generator.generate_fix_prompt(
                finding=finding.to_dict(),
                original_code=original_code
            )

            try:
                response = self.llm.messages.create(
                    model=self.model,
                    max_tokens=2048,
                    temperature=0.1,
                    messages=[{"role": "user", "content": fix_prompt}]
                )

                response_text = response.content[0].text

                # Parse fix
                json_start = response_text.find('{')
                json_end = response_text.rfind('}') + 1

                if json_start >= 0:
                    json_str = response_text[json_start:json_end]
                    fix_data = json.loads(json_str)
                    fixes[finding.id] = fix_data.get("fixed_code", original_code)

            except Exception as e:
                print(f"Fix generation error: {e}")
                # Fallback to suggested fix from finding
                fixes[finding.id] = finding.suggested_fix

        return fixes

    def apply_fixes(
        self,
        code: str,
        fixes: Dict[str, str]
    ) -> str:
        """
        Apply fixes to code.

        For now, this is simplified - just returns the first fix.
        In production, would need sophisticated code patching.

        Args:
            code: Original code
            fixes: Dict of fixes

        Returns:
            Fixed code
        """
        if not fixes:
            return code

        # Simplified: return first fix
        # Real implementation would need AST manipulation
        return list(fixes.values())[0]


if __name__ == "__main__":
    # Test defender agent
    import sys
    from pathlib import Path
    sys.path.insert(0, str(Path(__file__).parent.parent.parent))

    from src.knowledge.graph import SecurityKnowledgeGraph

    # Create knowledge graph
    kg = SecurityKnowledgeGraph()

    # Simulate some learning
    kg.update_pattern_effectiveness("PATTERN-SQL-001", is_true_positive=True)
    kg.update_pattern_effectiveness("PATTERN-SQL-001", is_true_positive=True)

    # Create defender
    if os.getenv("ANTHROPIC_API_KEY"):
        defender = DefenderAgent(knowledge_graph=kg)

        # Test code
        vulnerable_code = '''
def login(username, password):
    query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
    result = db.execute(query)
    return result
'''

        print("Analyzing vulnerable code...")
        trace = defender.analyze(vulnerable_code, language="python")

        print(f"\nAnalysis complete in {trace.time_taken:.2f}s")
        print(f"Findings: {len(trace.findings)}")

        for i, finding in enumerate(trace.findings, 1):
            print(f"\n{i}. [{finding.severity.upper()}] {finding.type}")
            print(f"   Location: {finding.location}")
            print(f"   Confidence: {finding.confidence:.0%}")
            print(f"   Explanation: {finding.explanation[:100]}...")

        if trace.findings:
            print("\nGenerating fixes...")
            fixes = defender.suggest_fixes(trace.findings, vulnerable_code)
            print(f"Generated {len(fixes)} fix(es)")

    else:
        print("Set ANTHROPIC_API_KEY to test defender agent")
