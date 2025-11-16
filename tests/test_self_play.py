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
        assert "fixes_broken" in metrics
        assert "novel_exploit_types" in metrics

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

    def test_attacker_reward_calculation(self):
        """Test attacker reward function"""
        from src.core.self_play import SelfPlayTrainer
        from src.knowledge.graph import SecurityKnowledgeGraph
        from src.agents.defender import DefenderAgent
        from src.agents.attacker import AttackerAgent
        from unittest.mock import Mock
        import tempfile

        kg = SecurityKnowledgeGraph(db_path=tempfile.mktemp())
        mock_llm = Mock()
        defender = DefenderAgent(kg, llm_client=mock_llm)
        attacker = AttackerAgent(llm_client=mock_llm)
        trainer = SelfPlayTrainer(kg, defender, attacker)

        # Test scenario: attacker found 2 FN, defender found 1 TP, 1 fix broken, 1 novel type
        metrics = {
            'false_negatives': 2,
            'true_positives': 1,
            'fixes_broken': 1,
            'novel_exploit_types': 1
        }

        attacker_reward = trainer._calculate_attacker_reward(metrics)

        # Expected: 15*2 + (-5)*1 + 25*1 + 10*1 = 30 - 5 + 25 + 10 = 60
        assert attacker_reward == 60.0

    def test_novel_exploit_detection(self):
        """Test detection of novel exploit types"""
        from src.core.self_play import SelfPlayTrainer
        from src.knowledge.graph import SecurityKnowledgeGraph
        from src.agents.defender import DefenderAgent
        from src.agents.attacker import AttackerAgent
        from unittest.mock import Mock
        import tempfile

        kg = SecurityKnowledgeGraph(db_path=tempfile.mktemp())
        mock_llm = Mock()
        defender = DefenderAgent(kg, llm_client=mock_llm)
        attacker = AttackerAgent(llm_client=mock_llm)
        trainer = SelfPlayTrainer(kg, defender, attacker)

        # First episode: sql_injection
        exploits1 = [
            Exploit("e1", "sql_injection", "CWE-89", "test", "line 1", True, "test", "test")
        ]

        metrics1 = trainer._calculate_metrics([], exploits1, [])
        assert metrics1["novel_exploit_types"] == 1  # First time seeing sql_injection

        # Second episode: sql_injection again + xss (new)
        exploits2 = [
            Exploit("e2", "sql_injection", "CWE-89", "test", "line 1", True, "test", "test"),
            Exploit("e3", "xss", "CWE-79", "test", "line 2", True, "test", "test")
        ]

        metrics2 = trainer._calculate_metrics([], exploits2, [])
        assert metrics2["novel_exploit_types"] == 1  # Only xss is new


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
