"""
Attacker Agent

Generates exploits and tests defenses.
Provides ground truth for defender training.
"""

import json
import os
import re
from typing import List, Dict, Optional
from dataclasses import dataclass, asdict
from datetime import datetime
from anthropic import Anthropic


@dataclass
class Exploit:
    """Successful exploit"""
    id: str
    type: str  # sql_injection, xss, command_injection, etc.
    cwe_id: Optional[str]
    payload: str
    target_location: str
    success: bool
    impact: str
    explanation: str

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class AttackTrace:
    """Trace of an attack attempt (for Agent Lightning)"""
    id: str
    code: str
    language: str
    exploits: List[Exploit]
    total_attempts: int
    success_rate: float
    time_taken: float
    timestamp: datetime

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "code": self.code,
            "language": self.language,
            "exploits_count": len(self.exploits),
            "exploits": [e.to_dict() for e in self.exploits],
            "total_attempts": self.total_attempts,
            "success_rate": self.success_rate,
            "time_taken": self.time_taken,
            "timestamp": self.timestamp.isoformat()
        }


class AttackerAgent:
    """
    Adversarial agent that attempts to exploit code.

    Provides ground truth for learning:
    - If attacker succeeds → real vulnerability
    - If attacker fails → false positive or secure code
    """

    def __init__(
        self,
        llm_client: Optional[Anthropic] = None,
        model: str = "claude-sonnet-4-5-20250929"
    ):
        self.model = model

        # Initialize LLM client
        if llm_client:
            self.llm = llm_client
        else:
            api_key = os.getenv("ANTHROPIC_API_KEY")
            if not api_key:
                raise ValueError("ANTHROPIC_API_KEY not set")
            self.llm = Anthropic(api_key=api_key)

        # Known exploit patterns (rule-based)
        self.exploit_patterns = self._init_exploit_patterns()

    def _init_exploit_patterns(self) -> Dict[str, List[str]]:
        """Initialize known exploit payloads"""
        return {
            "sql_injection": [
                "' OR '1'='1",
                "' OR 1=1--",
                "admin'--",
                "' UNION SELECT NULL--",
                "1' AND '1'='1",
            ],
            "xss": [
                "<script>alert('XSS')</script>",
                "<img src=x onerror=alert('XSS')>",
                "javascript:alert('XSS')",
                "<svg onload=alert('XSS')>",
            ],
            "command_injection": [
                "; ls -la",
                "| cat /etc/passwd",
                "&& whoami",
                "`id`",
                "$(cat /etc/passwd)",
            ],
            "path_traversal": [
                "../../../etc/passwd",
                "..\\..\\..\\windows\\system32\\config\\sam",
                "....//....//....//etc/passwd",
            ],
        }

    def attack(
        self,
        code: str,
        language: str = "python",
        context: Optional[Dict] = None
    ) -> AttackTrace:
        """
        Attempt to exploit code.

        Args:
            code: Code to attack
            language: Programming language
            context: Additional context

        Returns:
            AttackTrace with exploit results
        """
        start_time = datetime.now()
        exploits = []
        total_attempts = 0

        # Phase 1: Rule-based exploits
        rule_exploits, rule_attempts = self._try_rule_based_exploits(code)
        exploits.extend(rule_exploits)
        total_attempts += rule_attempts

        # Phase 2: LLM-powered creative exploits
        llm_exploits, llm_attempts = self._try_llm_exploits(code, language)
        exploits.extend(llm_exploits)
        total_attempts += llm_attempts

        end_time = datetime.now()
        time_taken = (end_time - start_time).total_seconds()

        success_rate = len(exploits) / total_attempts if total_attempts > 0 else 0.0

        trace = AttackTrace(
            id=f"attack-{datetime.now().timestamp()}",
            code=code,
            language=language,
            exploits=exploits,
            total_attempts=total_attempts,
            success_rate=success_rate,
            time_taken=time_taken,
            timestamp=start_time
        )

        return trace

    def _try_rule_based_exploits(self, code: str) -> tuple[List[Exploit], int]:
        """
        Try known exploit patterns against code.

        Returns:
            Tuple of (successful exploits, total attempts)
        """
        exploits = []
        attempts = 0

        # SQL Injection detection
        if self._looks_like_sql(code):
            for payload in self.exploit_patterns["sql_injection"]:
                attempts += 1
                if self._test_sql_injection(code, payload):
                    exploit = Exploit(
                        id=f"exploit-sql-{len(exploits)}",
                        type="sql_injection",
                        cwe_id="CWE-89",
                        payload=payload,
                        target_location=self._find_sql_location(code),
                        success=True,
                        impact="Database manipulation, authentication bypass",
                        explanation=f"Payload '{payload}' would bypass SQL query logic"
                    )
                    exploits.append(exploit)
                    break  # One successful exploit per type is enough

        # XSS detection
        if self._looks_like_frontend(code):
            for payload in self.exploit_patterns["xss"]:
                attempts += 1
                if self._test_xss(code, payload):
                    exploit = Exploit(
                        id=f"exploit-xss-{len(exploits)}",
                        type="xss",
                        cwe_id="CWE-79",
                        payload=payload,
                        target_location=self._find_xss_location(code),
                        success=True,
                        impact="JavaScript execution, session hijacking",
                        explanation=f"Payload '{payload}' would execute in browser"
                    )
                    exploits.append(exploit)
                    break

        # Command Injection detection
        if self._looks_like_shell_execution(code):
            for payload in self.exploit_patterns["command_injection"]:
                attempts += 1
                if self._test_command_injection(code, payload):
                    exploit = Exploit(
                        id=f"exploit-cmd-{len(exploits)}",
                        type="command_injection",
                        cwe_id="CWE-78",
                        payload=payload,
                        target_location=self._find_cmd_location(code),
                        success=True,
                        impact="Arbitrary command execution, system compromise",
                        explanation=f"Payload '{payload}' would execute system commands"
                    )
                    exploits.append(exploit)
                    break

        # Path Traversal detection
        if self._looks_like_file_operation(code):
            for payload in self.exploit_patterns["path_traversal"]:
                attempts += 1
                if self._test_path_traversal(code, payload):
                    exploit = Exploit(
                        id=f"exploit-path-{len(exploits)}",
                        type="path_traversal",
                        cwe_id="CWE-22",
                        payload=payload,
                        target_location=self._find_file_location(code),
                        success=True,
                        impact="Unauthorized file access",
                        explanation=f"Payload '{payload}' would access restricted files"
                    )
                    exploits.append(exploit)
                    break

        return exploits, attempts

    def _try_llm_exploits(
        self,
        code: str,
        language: str
    ) -> tuple[List[Exploit], int]:
        """
        Use LLM to discover creative exploits.

        Returns:
            Tuple of (successful exploits, total attempts)
        """
        exploits = []
        attempts = 1  # One LLM call

        prompt = f"""You are a penetration tester analyzing code for vulnerabilities.

CODE TO ATTACK:
```{language}
{code}
```

TASK:
Find potential security vulnerabilities and generate exploits to test them.

For each vulnerability:
1. Identify the vulnerability type
2. Generate a specific exploit payload
3. Explain what the exploit would achieve
4. Rate the likelihood it would work (0.0-1.0)

Be creative - look for:
- Logic flaws
- Input validation gaps
- Authentication bypasses
- Information disclosure
- Deserialization vulnerabilities

OUTPUT FORMAT (JSON):
{{
  "exploits": [
    {{
      "type": "sql_injection",
      "cwe_id": "CWE-89",
      "payload": "' OR 1=1--",
      "target_location": "line 42",
      "impact": "Authentication bypass",
      "explanation": "...",
      "confidence": 0.9
    }}
  ]
}}

Only include exploits you're confident would work (confidence > 0.6).
"""

        try:
            response = self.llm.messages.create(
                model=self.model,
                max_tokens=2048,
                temperature=0.3,  # Some creativity for exploit discovery
                messages=[{"role": "user", "content": prompt}]
            )

            response_text = response.content[0].text

            # Parse exploits
            json_start = response_text.find('{')
            json_end = response_text.rfind('}') + 1

            if json_start >= 0:
                json_str = response_text[json_start:json_end]
                data = json.loads(json_str)

                for e_data in data.get("exploits", []):
                    if e_data.get("confidence", 0) > 0.6:
                        exploit = Exploit(
                            id=f"exploit-llm-{len(exploits)}",
                            type=e_data.get("type", "unknown"),
                            cwe_id=e_data.get("cwe_id"),
                            payload=e_data.get("payload", ""),
                            target_location=e_data.get("target_location", "unknown"),
                            success=True,
                            impact=e_data.get("impact", ""),
                            explanation=e_data.get("explanation", "")
                        )
                        exploits.append(exploit)

        except Exception as e:
            print(f"LLM exploit generation error: {e}")

        return exploits, attempts

    # Helper methods for rule-based detection

    def _looks_like_sql(self, code: str) -> bool:
        """Check if code contains SQL operations"""
        sql_indicators = ["SELECT", "INSERT", "UPDATE", "DELETE", "execute", "query"]
        return any(indicator in code for indicator in sql_indicators)

    def _test_sql_injection(self, code: str, payload: str) -> bool:
        """Test if code is vulnerable to SQL injection"""
        # Look for string concatenation or formatting in SQL
        patterns = [
            r'f".*SELECT.*\{.*\}"',  # f-string in SQL
            r'".*SELECT.*%s".*%',     # % formatting
            r'".*SELECT.*\+',         # String concatenation
            r"'.*SELECT.*\{.*\}'",    # f-string with single quotes
        ]
        return any(re.search(pattern, code, re.IGNORECASE) for pattern in patterns)

    def _looks_like_frontend(self, code: str) -> bool:
        """Check if code contains frontend operations"""
        indicators = ["innerHTML", "document.write", "render", "dangerouslySetInnerHTML"]
        return any(indicator in code for indicator in indicators)

    def _test_xss(self, code: str, payload: str) -> bool:
        """Test if code is vulnerable to XSS"""
        patterns = [
            r'innerHTML\s*=\s*[^"]',  # Direct innerHTML assignment
            r'document\.write\(',      # document.write
            r'dangerouslySetInnerHTML',  # React dangerous HTML
        ]
        return any(re.search(pattern, code) for pattern in patterns)

    def _looks_like_shell_execution(self, code: str) -> bool:
        """Check if code executes shell commands"""
        indicators = ["os.system", "subprocess", "exec", "eval", "shell=True"]
        return any(indicator in code for indicator in indicators)

    def _test_command_injection(self, code: str, payload: str) -> bool:
        """Test if code is vulnerable to command injection"""
        patterns = [
            r'os\.system\(.*f"',           # os.system with f-string
            r'subprocess.*shell=True',     # subprocess with shell=True
            r'exec\(.*\+',                 # exec with concatenation
        ]
        return any(re.search(pattern, code) for pattern in patterns)

    def _looks_like_file_operation(self, code: str) -> bool:
        """Check if code performs file operations"""
        indicators = ["open(", "file", "Path(", "read", "write"]
        return any(indicator in code for indicator in indicators)

    def _test_path_traversal(self, code: str, payload: str) -> bool:
        """Test if code is vulnerable to path traversal"""
        patterns = [
            r'open\(.*f"',                 # open with f-string
            r'open\(.*\+',                 # open with concatenation
            r'Path\(.*\{.*\}',             # Path with variable
        ]
        return any(re.search(pattern, code) for pattern in patterns)

    # Location finders

    def _find_sql_location(self, code: str) -> str:
        """Find line with SQL vulnerability"""
        for i, line in enumerate(code.split('\n'), 1):
            if 'SELECT' in line or 'INSERT' in line:
                return f"line {i}"
        return "unknown"

    def _find_xss_location(self, code: str) -> str:
        """Find line with XSS vulnerability"""
        for i, line in enumerate(code.split('\n'), 1):
            if 'innerHTML' in line or 'document.write' in line:
                return f"line {i}"
        return "unknown"

    def _find_cmd_location(self, code: str) -> str:
        """Find line with command injection vulnerability"""
        for i, line in enumerate(code.split('\n'), 1):
            if 'os.system' in line or 'subprocess' in line:
                return f"line {i}"
        return "unknown"

    def _find_file_location(self, code: str) -> str:
        """Find line with path traversal vulnerability"""
        for i, line in enumerate(code.split('\n'), 1):
            if 'open(' in line or 'Path(' in line:
                return f"line {i}"
        return "unknown"


if __name__ == "__main__":
    # Test attacker agent
    if os.getenv("ANTHROPIC_API_KEY"):
        attacker = AttackerAgent()

        # Test code with SQL injection
        vulnerable_code = '''
def login(username, password):
    query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
    result = db.execute(query)
    return result
'''

        print("Attacking vulnerable code...")
        trace = attacker.attack(vulnerable_code, language="python")

        print(f"\nAttack complete in {trace.time_taken:.2f}s")
        print(f"Total attempts: {trace.total_attempts}")
        print(f"Successful exploits: {len(trace.exploits)}")
        print(f"Success rate: {trace.success_rate:.1%}")

        for i, exploit in enumerate(trace.exploits, 1):
            print(f"\n{i}. {exploit.type.upper()} ({exploit.cwe_id})")
            print(f"   Payload: {exploit.payload}")
            print(f"   Location: {exploit.target_location}")
            print(f"   Impact: {exploit.impact}")

    else:
        print("Set ANTHROPIC_API_KEY to test attacker agent")
