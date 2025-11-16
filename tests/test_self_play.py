"""
Tests for Self-Play Training Loop.
"""

import pytest
from datetime import datetime

from src.agents.defender import Finding
from src.agents.attacker import Exploit


class TestRewardCalculation:
    """Test reward function logic"""

    def test_true_positive_reward(self):
        """Test reward for true positive (defender found, attacker confirmed)"""
        from src.core.self_play import SelfPlayTrainer
        from src.knowledge.graph import SecurityKnowledgeGraph
        from src.agents.defender import DefenderAgent
        from src.agents.attacker import AttackerAgent
        import tempfile

        # Create temp knowledge graph
        kg = SecurityKnowledgeGraph(db_path=tempfile.mktemp())
        defender = DefenderAgent(kg)
        attacker = AttackerAgent()
        trainer = SelfPlayTrainer(kg, defender, attacker)

        metrics = trainer._calculate_metrics(
            defender_findings=[
                Finding(
                    id="f1",
                    type="sql_injection",
                    pattern_id="PATTERN-SQL-001",
                    cwe_id="CWE-89",
                    severity="critical",
                    location="line 1",
                    code_snippet="test",
                    explanation="test",
                    suggested_fix="test",
                    confidence=0.9
                )
            ],
            original_exploits=[
                Exploit(
                    id="e1",
                    type="sql_injection",
                    cwe_id="CWE-89",
                    payload="test",
                    target_location="line 1",
                    success=True,
                    impact="test",
                    explanation="test"
                )
            ],
            fixed_exploits=[]
        )

        assert metrics["true_positives"] == 1
        assert metrics["false_positives"] == 0
        assert metrics["false_negatives"] == 0

    def test_false_positive_detection(self):
        """Test false positive (defender found but attacker didn't)"""
        from src.core.self_play import SelfPlayTrainer
        from src.knowledge.graph import SecurityKnowledgeGraph
        from src.agents.defender import DefenderAgent
        from src.agents.attacker import AttackerAgent
        import tempfile

        kg = SecurityKnowledgeGraph(db_path=tempfile.mktemp())
        defender = DefenderAgent(kg)
        attacker = AttackerAgent()
        trainer = SelfPlayTrainer(kg, defender, attacker)

        metrics = trainer._calculate_metrics(
            defender_findings=[
                Finding(
                    id="f1",
                    type="xss",
                    pattern_id="PATTERN-XSS-001",
                    cwe_id="CWE-79",
                    severity="high",
                    location="line 1",
                    code_snippet="test",
                    explanation="test",
                    suggested_fix="test",
                    confidence=0.7
                )
            ],
            original_exploits=[
                # Attacker found SQL injection, not XSS
                Exploit(
                    id="e1",
                    type="sql_injection",
                    cwe_id="CWE-89",
                    payload="test",
                    target_location="line 1",
                    success=True,
                    impact="test",
                    explanation="test"
                )
            ],
            fixed_exploits=[]
        )

        assert metrics["false_positives"] == 1
        assert metrics["true_positives"] == 0

    def test_false_negative_detection(self):
        """Test false negative (attacker found but defender didn't)"""
        from src.core.self_play import SelfPlayTrainer
        from src.knowledge.graph import SecurityKnowledgeGraph
        from src.agents.defender import DefenderAgent
        from src.agents.attacker import AttackerAgent
        import tempfile

        kg = SecurityKnowledgeGraph(db_path=tempfile.mktemp())
        defender = DefenderAgent(kg)
        attacker = AttackerAgent()
        trainer = SelfPlayTrainer(kg, defender, attacker)

        metrics = trainer._calculate_metrics(
            defender_findings=[],  # Defender found nothing
            original_exploits=[
                Exploit(
                    id="e1",
                    type="sql_injection",
                    cwe_id="CWE-89",
                    payload="test",
                    target_location="line 1",
                    success=True,
                    impact="test",
                    explanation="test"
                )
            ],
            fixed_exploits=[]
        )

        assert metrics["false_negatives"] == 1
        assert metrics["true_positives"] == 0

    def test_fixes_that_worked(self):
        """Test counting fixes that successfully blocked exploits"""
        from src.core.self_play import SelfPlayTrainer
        from src.knowledge.graph import SecurityKnowledgeGraph
        from src.agents.defender import DefenderAgent
        from src.agents.attacker import AttackerAgent
        import tempfile

        kg = SecurityKnowledgeGraph(db_path=tempfile.mktemp())
        defender = DefenderAgent(kg)
        attacker = AttackerAgent()
        trainer = SelfPlayTrainer(kg, defender, attacker)

        # Original had 3 exploits, fixed has only 1
        original_exploits = [
            Exploit(f"e{i}", "sql_injection", "CWE-89", "test", "line 1", True, "test", "test")
            for i in range(3)
        ]

        fixed_exploits = [original_exploits[0]]  # One still works

        metrics = trainer._calculate_metrics(
            defender_findings=[],
            original_exploits=original_exploits,
            fixed_exploits=fixed_exploits
        )

        # 3 - 1 = 2 fixes worked
        assert metrics["fixes_that_worked"] == 2


class TestMatchingLogic:
    """Test exploit-finding matching logic"""

    def test_match_by_cwe(self):
        """Test matching by CWE ID"""
        from src.core.self_play import SelfPlayTrainer
        from src.knowledge.graph import SecurityKnowledgeGraph
        from src.agents.defender import DefenderAgent
        from src.agents.attacker import AttackerAgent
        import tempfile

        kg = SecurityKnowledgeGraph(db_path=tempfile.mktemp())
        defender = DefenderAgent(kg)
        attacker = AttackerAgent()
        trainer = SelfPlayTrainer(kg, defender, attacker)

        finding = Finding(
            id="f1",
            type="SQL Injection",
            pattern_id="PATTERN-SQL-001",
            cwe_id="CWE-89",
            severity="critical",
            location="line 1",
            code_snippet="test",
            explanation="test",
            suggested_fix="test",
            confidence=0.9
        )

        exploit = Exploit(
            id="e1",
            type="sql_injection",
            cwe_id="CWE-89",
            payload="test",
            target_location="line 1",
            success=True,
            impact="test",
            explanation="test"
        )

        assert trainer._matches(finding, exploit)

    def test_match_by_type_fuzzy(self):
        """Test fuzzy matching by type"""
        from src.core.self_play import SelfPlayTrainer
        from src.knowledge.graph import SecurityKnowledgeGraph
        from src.agents.defender import DefenderAgent
        from src.agents.attacker import AttackerAgent
        import tempfile

        kg = SecurityKnowledgeGraph(db_path=tempfile.mktemp())
        defender = DefenderAgent(kg)
        attacker = AttackerAgent()
        trainer = SelfPlayTrainer(kg, defender, attacker)

        finding = Finding(
            id="f1",
            type="Command Injection",
            pattern_id="PATTERN-CMD-001",
            cwe_id=None,
            severity="critical",
            location="line 1",
            code_snippet="test",
            explanation="test",
            suggested_fix="test",
            confidence=0.9
        )

        exploit = Exploit(
            id="e1",
            type="command_injection",
            cwe_id=None,
            payload="test",
            target_location="line 1",
            success=True,
            impact="test",
            explanation="test"
        )

        assert trainer._matches(finding, exploit)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
