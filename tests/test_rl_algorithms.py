"""
Tests for RL algorithms (GRPO, PromptOptimizer).
"""

import pytest
import numpy as np
from datetime import datetime

from src.rl.store import LightningStore, Trace, Span
from src.rl.algorithms import GRPO, PromptOptimizer, PolicyUpdate


class TestGRPO:
    """Test GRPO algorithm"""

    def test_initialization(self, test_rl_store):
        """Test GRPO initializes"""
        grpo = GRPO(test_rl_store)

        assert grpo.store == test_rl_store
        assert grpo.batch_size > 0
        assert 0 <= grpo.exploration_rate <= 1

    def test_normalize_rewards(self, test_rl_store):
        """Test reward normalization"""
        grpo = GRPO(test_rl_store)

        rewards = [10.0, 20.0, 30.0, 40.0, 50.0]
        normalized = grpo.normalize_rewards(rewards)

        # Should be approximately zero mean
        assert abs(np.mean(normalized)) < 0.01

        # Should have unit variance (approximately)
        assert abs(np.std(normalized) - 1.0) < 0.01

    def test_normalize_rewards_single_value(self, test_rl_store):
        """Test normalization with single reward"""
        grpo = GRPO(test_rl_store)

        rewards = [10.0]
        normalized = grpo.normalize_rewards(rewards)

        assert len(normalized) == 1

    def test_compute_pattern_scores(self, test_rl_store):
        """Test pattern score computation"""
        grpo = GRPO(test_rl_store)

        patterns_per_trace = [
            ["PATTERN-A", "PATTERN-B"],
            ["PATTERN-A", "PATTERN-C"],
            ["PATTERN-B", "PATTERN-C"],
        ]

        rewards = np.array([10.0, 20.0, 15.0])

        scores = grpo._compute_pattern_scores(patterns_per_trace, rewards)

        # PATTERN-A appears in traces with rewards 10, 20 -> avg 15
        assert abs(scores["PATTERN-A"] - 15.0) < 0.01

        # PATTERN-B appears in traces with rewards 10, 15 -> avg 12.5
        assert abs(scores["PATTERN-B"] - 12.5) < 0.01

        # PATTERN-C appears in traces with rewards 20, 15 -> avg 17.5
        assert abs(scores["PATTERN-C"] - 17.5) < 0.01

    def test_compute_update_insufficient_data(self, test_rl_store):
        """Test compute_update with insufficient traces"""
        grpo = GRPO(test_rl_store)

        # Only one trace
        traces = [
            Trace(
                trace_id="test-1",
                agent_name="defender",
                episode_number=1,
                spans=[],
                reward=10.0
            )
        ]

        update = grpo.compute_update(traces)
        assert update is None

    def test_compute_update_with_data(self, test_rl_store):
        """Test compute_update with sufficient traces"""
        grpo = GRPO(test_rl_store)

        # Create traces with patterns
        traces = []
        for i in range(5):
            spans = [
                Span(
                    span_id=f"span-{i}",
                    trace_id=f"trace-{i}",
                    span_type="patterns_checked",
                    timestamp=datetime.now(),
                    data={"patterns": [f"PATTERN-{i % 3}"]}
                )
            ]

            trace = Trace(
                trace_id=f"trace-{i}",
                agent_name="defender",
                episode_number=i,
                spans=spans,
                reward=10.0 + i * 5.0
            )
            traces.append(trace)

        update = grpo.compute_update(traces)

        assert update is not None
        assert isinstance(update, PolicyUpdate)
        assert update.resource_type == "prompt_strategy"
        assert 0 <= update.confidence <= 1

    def test_get_pattern_recommendations(self, test_rl_store):
        """Test getting pattern recommendations"""
        grpo = GRPO(test_rl_store)

        # Simulate some pattern scores
        grpo.pattern_scores["PATTERN-A"] = [10.0, 15.0, 20.0, 12.0, 18.0, 16.0]
        grpo.pattern_scores["PATTERN-B"] = [5.0, 6.0, 7.0, 8.0, 9.0, 10.0]
        grpo.pattern_scores["PATTERN-C"] = [2.0, 3.0, 1.0]  # Too few observations

        recommendations = grpo.get_pattern_recommendations(min_observations=5)

        # Should have A and B but not C
        pattern_ids = [p[0] for p in recommendations]
        assert "PATTERN-A" in pattern_ids
        assert "PATTERN-B" in pattern_ids
        assert "PATTERN-C" not in pattern_ids

        # Should be sorted by score (A has higher average than B)
        if len(recommendations) >= 2:
            assert recommendations[0][1] > recommendations[1][1]


class TestPromptOptimizer:
    """Test PromptOptimizer"""

    def test_initialization(self, test_rl_store):
        """Test optimizer initializes"""
        optimizer = PromptOptimizer(test_rl_store)
        assert optimizer.store == test_rl_store

    def test_generate_variations(self, test_rl_store):
        """Test prompt variation generation"""
        optimizer = PromptOptimizer(test_rl_store)

        base_prompt = "Analyze this code for security vulnerabilities"
        variations = optimizer.generate_variations(base_prompt, num_variations=3)

        assert len(variations) <= 3
        assert base_prompt in variations  # Should include original

    def test_select_best_prompt(self, test_rl_store):
        """Test selecting best performing prompt"""
        optimizer = PromptOptimizer(test_rl_store)

        prompt_results = [
            ("prompt A", 10.0),
            ("prompt B", 25.0),
            ("prompt C", 15.0),
        ]

        best = optimizer.select_best_prompt(prompt_results)
        assert best == "prompt B"

    def test_select_best_prompt_empty(self, test_rl_store):
        """Test selecting from empty results"""
        optimizer = PromptOptimizer(test_rl_store)

        best = optimizer.select_best_prompt([])
        assert best == ""


class TestPolicyUpdate:
    """Test PolicyUpdate dataclass"""

    def test_policy_update_creation(self):
        """Test creating a policy update"""
        update = PolicyUpdate(
            resource_type="prompt_strategy",
            content="test strategy",
            expected_improvement=5.0,
            confidence=0.85,
            metadata={"test": "data"}
        )

        assert update.resource_type == "prompt_strategy"
        assert update.expected_improvement == 5.0
        assert update.confidence == 0.85


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
