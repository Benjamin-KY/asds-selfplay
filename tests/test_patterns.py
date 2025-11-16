"""
Tests for security pattern library.
"""

import pytest
import tempfile

from src.patterns.library import (
    initialize_pattern_library,
    get_all_patterns,
    get_sql_injection_patterns,
    get_command_injection_patterns,
    get_xss_patterns,
    get_authentication_patterns,
    get_crypto_patterns,
    get_ssrf_patterns,
    get_path_traversal_patterns,
    get_csrf_patterns,
    get_regex_dos_patterns,
    get_race_condition_patterns,
    get_open_redirect_patterns,
)
from src.knowledge.graph import SecurityKnowledgeGraph, PatternType


class TestPatternLibrary:
    """Test pattern library functions"""

    def test_get_all_patterns_count(self):
        """Test that we have 52+ patterns"""
        patterns = get_all_patterns()

        assert len(patterns) >= 52, f"Expected 52+ patterns, got {len(patterns)}"

    def test_get_all_patterns_unique_ids(self):
        """Test that all pattern IDs are unique"""
        patterns = get_all_patterns()
        pattern_ids = [p.id for p in patterns]

        assert len(pattern_ids) == len(set(pattern_ids)), "Duplicate pattern IDs found"

    def test_pattern_categories_coverage(self):
        """Test that all major vulnerability categories are covered"""
        patterns = get_all_patterns()
        pattern_types = {p.pattern_type for p in patterns}

        # Should cover major OWASP Top 10 categories
        expected_types = {
            PatternType.SQL_INJECTION,
            PatternType.XSS,
            PatternType.COMMAND_INJECTION,
            PatternType.AUTHENTICATION_BYPASS,
            PatternType.PATH_TRAVERSAL,
            PatternType.INSECURE_DESERIALIZATION,
            PatternType.CSRF,
            PatternType.XXE,
            PatternType.SSRF,
            PatternType.HARDCODED_SECRETS,
        }

        assert expected_types.issubset(pattern_types), \
            f"Missing pattern types: {expected_types - pattern_types}"

    def test_risk_level_distribution(self):
        """Test pattern risk level distribution"""
        patterns = get_all_patterns()
        risk_levels = [p.risk_level for p in patterns]

        # Should have critical, high, and medium risk patterns
        assert "critical" in risk_levels, "No critical risk patterns"
        assert "high" in risk_levels, "No high risk patterns"
        assert "medium" in risk_levels, "No medium risk patterns"

        # Count distribution
        critical_count = risk_levels.count("critical")
        high_count = risk_levels.count("high")
        medium_count = risk_levels.count("medium")

        assert critical_count >= 10, f"Expected at least 10 critical patterns, got {critical_count}"
        assert high_count >= 15, f"Expected at least 15 high patterns, got {high_count}"

    def test_language_support(self):
        """Test multi-language support"""
        patterns = get_all_patterns()
        languages = {p.language for p in patterns}

        # Should support at least Python and JavaScript
        assert "python" in languages, "No Python patterns"
        assert "javascript" in languages, "No JavaScript patterns"

        # Most patterns should be Python
        python_count = sum(1 for p in patterns if p.language == "python")
        assert python_count >= 40, f"Expected at least 40 Python patterns, got {python_count}"

    def test_cwe_coverage(self):
        """Test CWE identifier coverage"""
        patterns = get_all_patterns()
        cwe_ids = {p.cwe_id for p in patterns if p.cwe_id}

        # Should have 20+ unique CWE IDs
        assert len(cwe_ids) >= 20, f"Expected 20+ CWE IDs, got {len(cwe_ids)}"

        # Check for major CWEs
        major_cwes = {"CWE-89", "CWE-79", "CWE-78", "CWE-798", "CWE-22"}
        assert major_cwes.issubset(cwe_ids), \
            f"Missing major CWEs: {major_cwes - cwe_ids}"

    def test_pattern_structure(self):
        """Test that all patterns have required fields"""
        patterns = get_all_patterns()

        for pattern in patterns:
            # Required fields
            assert pattern.id, f"Pattern missing ID: {pattern}"
            assert pattern.name, f"Pattern {pattern.id} missing name"
            assert pattern.pattern_type, f"Pattern {pattern.id} missing type"
            assert pattern.code_example, f"Pattern {pattern.id} missing code example"
            assert pattern.language, f"Pattern {pattern.id} missing language"
            assert pattern.risk_level, f"Pattern {pattern.id} missing risk level"

            # ID format
            assert pattern.id.startswith("PATTERN-"), \
                f"Pattern {pattern.id} doesn't follow ID format"

            # Risk level validation
            assert pattern.risk_level in ["critical", "high", "medium", "low"], \
                f"Pattern {pattern.id} has invalid risk level: {pattern.risk_level}"

    def test_initialize_pattern_library(self, temp_dir):
        """Test initializing knowledge graph with pattern library"""
        kg = SecurityKnowledgeGraph(db_path=str(temp_dir / "test_kg.db"))

        count = initialize_pattern_library(kg)

        assert count >= 52, f"Expected 52+ patterns initialized, got {count}"

        # Verify patterns are in knowledge graph
        stats = kg.get_stats()
        assert stats["total_patterns"] == count

    def test_pattern_categories(self):
        """Test individual pattern category functions"""
        sql_patterns = get_sql_injection_patterns()
        assert len(sql_patterns) >= 3, "Expected at least 3 SQL injection patterns"

        cmd_patterns = get_command_injection_patterns()
        assert len(cmd_patterns) >= 3, "Expected at least 3 command injection patterns"

        xss_patterns = get_xss_patterns()
        assert len(xss_patterns) >= 4, "Expected at least 4 XSS patterns"

        auth_patterns = get_authentication_patterns()
        assert len(auth_patterns) >= 4, "Expected at least 4 authentication patterns"

        crypto_patterns = get_crypto_patterns()
        assert len(crypto_patterns) >= 4, "Expected at least 4 crypto patterns"

        ssrf_patterns = get_ssrf_patterns()
        assert len(ssrf_patterns) >= 2, "Expected at least 2 SSRF patterns"

        path_patterns = get_path_traversal_patterns()
        assert len(path_patterns) >= 2, "Expected at least 2 path traversal patterns"

        csrf_patterns = get_csrf_patterns()
        assert len(csrf_patterns) >= 2, "Expected at least 2 CSRF patterns"

        redos_patterns = get_regex_dos_patterns()
        assert len(redos_patterns) >= 2, "Expected at least 2 RegEx DoS patterns"

        race_patterns = get_race_condition_patterns()
        assert len(race_patterns) >= 2, "Expected at least 2 race condition patterns"

        redirect_patterns = get_open_redirect_patterns()
        assert len(redirect_patterns) >= 2, "Expected at least 2 open redirect patterns"


class TestPatternContent:
    """Test specific pattern content and examples"""

    def test_sql_injection_patterns(self):
        """Test SQL injection pattern content"""
        patterns = get_sql_injection_patterns()

        # Check for string formatting pattern
        pattern_ids = [p.id for p in patterns]
        assert "PATTERN-SQL-001" in pattern_ids

        # Verify code examples contain SQL keywords
        for pattern in patterns:
            assert "SELECT" in pattern.code_example.upper() or \
                   "INSERT" in pattern.code_example.upper() or \
                   "UPDATE" in pattern.code_example.upper(), \
                f"Pattern {pattern.id} doesn't look like SQL injection"

    def test_command_injection_patterns(self):
        """Test command injection pattern content"""
        patterns = get_command_injection_patterns()

        # Should have patterns for subprocess, os.system, etc.
        code_examples = [p.code_example for p in patterns]
        combined = " ".join(code_examples)

        assert "subprocess" in combined or "os.system" in combined or "exec" in combined, \
            "Missing common command injection vectors"

    def test_xss_patterns(self):
        """Test XSS pattern content"""
        patterns = get_xss_patterns()

        # Should cover reflected, stored, DOM-based
        names = [p.name.lower() for p in patterns]
        combined = " ".join(names)

        assert "reflected" in combined or "stored" in combined or "dom" in combined, \
            "Missing XSS variant coverage"

    def test_hardcoded_secrets_patterns(self):
        """Test hardcoded secrets pattern detection"""
        patterns = get_all_patterns()
        secret_patterns = [p for p in patterns if p.pattern_type == PatternType.HARDCODED_SECRETS]

        assert len(secret_patterns) >= 4, "Need more hardcoded secrets patterns"

        # Should cover API keys, passwords, etc.
        code_examples = [p.code_example for p in secret_patterns]
        combined = " ".join(code_examples).lower()

        assert "password" in combined or "api_key" in combined or "secret" in combined, \
            "Missing common secret types"

    def test_crypto_patterns(self):
        """Test cryptographic failure patterns"""
        patterns = get_crypto_patterns()

        # Should cover weak algorithms, hardcoded keys, etc.
        names = [p.name.lower() for p in patterns]
        combined = " ".join(names)

        assert "weak" in combined or "insecure" in combined or "hardcoded" in combined, \
            "Missing crypto weakness indicators"


class TestPatternIntegration:
    """Test pattern integration with knowledge graph"""

    def test_patterns_add_to_knowledge_graph(self, temp_dir):
        """Test adding patterns to knowledge graph"""
        kg = SecurityKnowledgeGraph(db_path=str(temp_dir / "test_kg.db"))

        # Note: SecurityKnowledgeGraph initializes with 8 base patterns
        initial_count = kg.get_stats()["total_patterns"]

        # Get first 5 patterns (some may overlap with base patterns)
        patterns = get_all_patterns()[:5]

        for pattern in patterns:
            kg.add_pattern(pattern)

        # Verify patterns were added (some might replace existing ones)
        final_count = kg.get_stats()["total_patterns"]
        assert final_count >= 5, f"Expected at least 5 patterns, got {final_count}"

        # Verify specific patterns are present
        for pattern in patterns:
            retrieved = kg.get_pattern(pattern.id)
            assert retrieved is not None, f"Pattern {pattern.id} not found"
            assert retrieved.id == pattern.id

    def test_pattern_retrieval_from_graph(self, temp_dir):
        """Test retrieving patterns from knowledge graph"""
        kg = SecurityKnowledgeGraph(db_path=str(temp_dir / "test_kg.db"))
        initialize_pattern_library(kg)

        # Retrieve specific pattern
        pattern = kg.get_pattern("PATTERN-SQL-001")
        assert pattern is not None
        assert pattern.id == "PATTERN-SQL-001"
        assert pattern.pattern_type == PatternType.SQL_INJECTION

    def test_pattern_effectiveness_metrics(self, temp_dir):
        """Test that patterns have effectiveness metrics initialized"""
        kg = SecurityKnowledgeGraph(db_path=str(temp_dir / "test_kg.db"))
        initialize_pattern_library(kg)

        patterns = kg.get_all_patterns()

        for pattern in patterns:
            # New patterns should have zero observations
            assert pattern.observations == 0
            assert pattern.true_positives == 0
            assert pattern.false_positives == 0
            assert pattern.false_negatives == 0

            # Effectiveness should be neutral (0.5) for new patterns
            assert pattern.effectiveness == 0.5

    def test_get_effective_patterns_initial(self, temp_dir):
        """Test getting effective patterns when none have data"""
        kg = SecurityKnowledgeGraph(db_path=str(temp_dir / "test_kg.db"))
        initialize_pattern_library(kg)

        # With no observations, should return some patterns based on recency
        effective = kg.get_effective_patterns(limit=5)

        # Should return something (or empty if no patterns meet criteria)
        assert isinstance(effective, list)

    def test_pattern_persistence(self, temp_dir):
        """Test that patterns persist across sessions"""
        db_path = temp_dir / "test_kg.db"

        # First session: initialize patterns
        kg1 = SecurityKnowledgeGraph(db_path=str(db_path))
        count1 = initialize_pattern_library(kg1)
        kg1.save()

        # Second session: load patterns
        kg2 = SecurityKnowledgeGraph(db_path=str(db_path))
        count2 = kg2.get_stats()["total_patterns"]

        assert count1 == count2, "Pattern count mismatch after persistence"


class TestPatternCoverage:
    """Test coverage of specific vulnerability types"""

    def test_owasp_top_10_coverage(self):
        """Test coverage of OWASP Top 10 vulnerability types"""
        patterns = get_all_patterns()
        pattern_names = [p.name.lower() for p in patterns]
        combined = " ".join(pattern_names)

        # OWASP Top 10 2021 categories (partial check)
        assert "injection" in combined, "Missing injection patterns"
        assert "authentication" in combined or "auth" in combined, "Missing auth patterns"
        assert "xss" in combined or "cross-site" in combined, "Missing XSS patterns"
        assert "deserialization" in combined, "Missing deserialization patterns"
        assert "ssrf" in combined, "Missing SSRF patterns"

    def test_cwe_top_25_coverage(self):
        """Test coverage of CWE Top 25 dangerous weaknesses"""
        patterns = get_all_patterns()
        cwe_ids = {p.cwe_id for p in patterns if p.cwe_id}

        # Sample from CWE Top 25
        important_cwes = {
            "CWE-89",   # SQL Injection
            "CWE-79",   # XSS
            "CWE-78",   # OS Command Injection
            "CWE-20",   # Improper Input Validation (covered by various)
            "CWE-798",  # Hardcoded Credentials
            "CWE-22",   # Path Traversal
            "CWE-352",  # CSRF
            "CWE-502",  # Deserialization
        }

        covered = important_cwes.intersection(cwe_ids)
        coverage_pct = len(covered) / len(important_cwes) * 100

        assert coverage_pct >= 75, \
            f"Only {coverage_pct:.0f}% coverage of important CWEs. Missing: {important_cwes - covered}"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
