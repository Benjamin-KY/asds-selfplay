"""
Tests for SecurityKnowledgeGraph.
"""

import pytest
from src.knowledge.graph import (
    SecurityKnowledgeGraph,
    SecurityPattern,
    PatternType
)


class TestSecurityPattern:
    """Test SecurityPattern dataclass"""

    def test_pattern_creation(self, sample_pattern):
        """Test pattern can be created"""
        assert sample_pattern.id == "TEST-PATTERN-001"
        assert sample_pattern.pattern_type == PatternType.SQL_INJECTION
        assert sample_pattern.observations == 0

    def test_precision_calculation(self, sample_pattern):
        """Test precision metric"""
        sample_pattern.true_positives = 8
        sample_pattern.false_positives = 2
        assert sample_pattern.precision == 0.8

    def test_precision_zero_division(self, sample_pattern):
        """Test precision with no data"""
        assert sample_pattern.precision == 0.0

    def test_recall_calculation(self, sample_pattern):
        """Test recall metric"""
        sample_pattern.true_positives = 7
        sample_pattern.false_negatives = 3
        assert sample_pattern.recall == 0.7

    def test_f1_score(self, sample_pattern):
        """Test F1 score calculation"""
        sample_pattern.true_positives = 8
        sample_pattern.false_positives = 2
        sample_pattern.false_negatives = 2

        # Precision = 8/10 = 0.8
        # Recall = 8/10 = 0.8
        # F1 = 2 * (0.8 * 0.8) / (0.8 + 0.8) = 0.8
        assert sample_pattern.f1_score == 0.8

    def test_effectiveness_with_few_observations(self, sample_pattern):
        """Test effectiveness returns neutral for new patterns"""
        sample_pattern.observations = 2
        assert sample_pattern.effectiveness == 0.5

    def test_effectiveness_with_data(self, sample_pattern):
        """Test effectiveness uses F1 with enough data"""
        sample_pattern.observations = 10
        sample_pattern.true_positives = 8
        sample_pattern.false_positives = 1
        sample_pattern.false_negatives = 1

        assert sample_pattern.effectiveness == sample_pattern.f1_score


class TestSecurityKnowledgeGraph:
    """Test SecurityKnowledgeGraph"""

    def test_initialization(self, test_knowledge_graph):
        """Test knowledge graph initializes"""
        assert test_knowledge_graph is not None
        assert len(test_knowledge_graph.patterns) > 0  # Has base patterns

    def test_base_patterns_loaded(self, test_knowledge_graph):
        """Test base patterns are loaded"""
        # Should have SQL, XSS, CMD, PATH patterns
        sql_patterns = [
            p for p in test_knowledge_graph.patterns.values()
            if p.pattern_type == PatternType.SQL_INJECTION
        ]
        assert len(sql_patterns) >= 2

    def test_add_pattern(self, test_knowledge_graph, sample_pattern):
        """Test adding a new pattern"""
        test_knowledge_graph.add_pattern(sample_pattern)

        assert sample_pattern.id in test_knowledge_graph.patterns
        retrieved = test_knowledge_graph.patterns[sample_pattern.id]
        assert retrieved.name == sample_pattern.name

    def test_update_pattern_effectiveness_true_positive(
        self,
        test_knowledge_graph
    ):
        """Test updating pattern with true positive"""
        pattern_id = "PATTERN-SQL-001"

        initial_tp = test_knowledge_graph.patterns[pattern_id].true_positives

        test_knowledge_graph.update_pattern_effectiveness(
            pattern_id,
            is_true_positive=True
        )

        pattern = test_knowledge_graph.patterns[pattern_id]
        assert pattern.true_positives == initial_tp + 1
        assert pattern.observations > 0

    def test_update_pattern_effectiveness_false_positive(
        self,
        test_knowledge_graph
    ):
        """Test updating pattern with false positive"""
        pattern_id = "PATTERN-SQL-001"

        initial_fp = test_knowledge_graph.patterns[pattern_id].false_positives

        test_knowledge_graph.update_pattern_effectiveness(
            pattern_id,
            is_true_positive=False,
            is_false_negative=False
        )

        pattern = test_knowledge_graph.patterns[pattern_id]
        assert pattern.false_positives == initial_fp + 1

    def test_update_pattern_effectiveness_false_negative(
        self,
        test_knowledge_graph
    ):
        """Test updating pattern with false negative"""
        pattern_id = "PATTERN-SQL-001"

        initial_fn = test_knowledge_graph.patterns[pattern_id].false_negatives

        test_knowledge_graph.update_pattern_effectiveness(
            pattern_id,
            is_true_positive=False,
            is_false_negative=True
        )

        pattern = test_knowledge_graph.patterns[pattern_id]
        assert pattern.false_negatives == initial_fn + 1

    def test_get_effective_patterns(self, test_knowledge_graph):
        """Test retrieving effective patterns"""
        # Add some observations to a pattern
        pattern_id = "PATTERN-SQL-001"

        for _ in range(5):
            test_knowledge_graph.update_pattern_effectiveness(
                pattern_id,
                is_true_positive=True
            )

        effective = test_knowledge_graph.get_effective_patterns(
            min_effectiveness=0.7,
            min_observations=3
        )

        # Should find at least one effective pattern
        assert len(effective) > 0
        assert all(p.effectiveness >= 0.7 for p in effective)
        assert all(p.observations >= 3 for p in effective)

    def test_get_ineffective_patterns(self, test_knowledge_graph):
        """Test retrieving ineffective patterns"""
        # Create a pattern with poor performance
        pattern_id = "TEST-PATTERN-BAD"
        bad_pattern = SecurityPattern(
            id=pattern_id,
            name="Bad Pattern",
            pattern_type=PatternType.SQL_INJECTION,
            code_example="test",
            language="python",
            risk_level="low",
            observations=15,
            true_positives=1,
            false_positives=14,
            false_negatives=0
        )

        test_knowledge_graph.add_pattern(bad_pattern)

        ineffective = test_knowledge_graph.get_ineffective_patterns(
            max_effectiveness=0.3,
            min_observations=10
        )

        # Should find the bad pattern
        pattern_ids = [p.id for p in ineffective]
        assert pattern_id in pattern_ids

    def test_prune_ineffective_patterns(self, test_knowledge_graph):
        """Test pruning ineffective patterns"""
        # Create ineffective pattern
        pattern_id = "TEST-PRUNE"
        prune_pattern = SecurityPattern(
            id=pattern_id,
            name="Prune Pattern",
            pattern_type=PatternType.XSS,
            code_example="test",
            language="python",
            risk_level="low",
            observations=25,
            true_positives=1,
            false_positives=24,
            false_negatives=0
        )

        test_knowledge_graph.add_pattern(prune_pattern)

        initial_count = len(test_knowledge_graph.patterns)

        pruned = test_knowledge_graph.prune_ineffective_patterns(
            max_effectiveness=0.2,
            min_observations=20
        )

        assert pruned >= 1
        assert len(test_knowledge_graph.patterns) < initial_count
        assert pattern_id not in test_knowledge_graph.patterns

    def test_get_stats(self, test_knowledge_graph):
        """Test getting statistics"""
        stats = test_knowledge_graph.get_stats()

        assert 'total_patterns' in stats
        assert 'total_observations' in stats
        assert 'avg_effectiveness' in stats
        assert 'patterns_by_type' in stats

        assert stats['total_patterns'] > 0
        assert isinstance(stats['patterns_by_type'], dict)

    def test_persistence(self, test_knowledge_graph, sample_pattern):
        """Test patterns persist to database"""
        # Add pattern
        test_knowledge_graph.add_pattern(sample_pattern)

        # Update it
        test_knowledge_graph.update_pattern_effectiveness(
            sample_pattern.id,
            is_true_positive=True
        )

        # Create new graph instance with same DB
        db_path = test_knowledge_graph.db_path
        new_graph = SecurityKnowledgeGraph(db_path=str(db_path))

        # Pattern should exist with updated values
        assert sample_pattern.id in new_graph.patterns
        pattern = new_graph.patterns[sample_pattern.id]
        assert pattern.true_positives == 1
        assert pattern.observations == 1


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
