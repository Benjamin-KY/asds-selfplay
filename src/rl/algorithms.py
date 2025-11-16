"""
RL Algorithms for prompt and strategy optimization.

Implements GRPO (Group Relative Policy Optimization) and other
algorithms for optimizing agent behavior.
"""

import numpy as np
from typing import List, Dict, Optional, Any, Tuple
from dataclasses import dataclass
from collections import defaultdict

from src.rl.store import Trace, LightningStore
from src.utils.logging_config import get_logger
from src.utils.config import get_config

logger = get_logger(__name__)


@dataclass
class PolicyUpdate:
    """Represents a policy update"""
    resource_type: str
    content: str
    expected_improvement: float
    confidence: float
    metadata: Dict[str, Any]


class PolicyOptimizer:
    """
    Base class for policy optimization algorithms.
    """

    def __init__(self, store: LightningStore, config: Optional[Dict] = None):
        self.store = store
        self.config = config or {}
        self.learning_rate = self.config.get('learning_rate', 1e-4)

    def compute_update(self, traces: List[Trace]) -> Optional[PolicyUpdate]:
        """
        Compute policy update from traces.

        Args:
            traces: List of execution traces with rewards

        Returns:
            PolicyUpdate or None if insufficient data
        """
        raise NotImplementedError("Subclasses must implement compute_update")

    def normalize_rewards(self, rewards: List[float]) -> np.ndarray:
        """Normalize rewards for training stability"""
        rewards_array = np.array(rewards)

        if len(rewards) < 2:
            return rewards_array

        mean = np.mean(rewards_array)
        std = np.std(rewards_array)

        if std < 1e-8:
            return rewards_array - mean

        return (rewards_array - mean) / (std + 1e-8)


class GRPO(PolicyOptimizer):
    """
    Group Relative Policy Optimization.

    Optimizes prompt selection and strategy based on relative performance
    within groups of episodes.

    Key ideas:
    - Compare performance within batches (groups)
    - Update based on which patterns/strategies performed best
    - Use relative rankings rather than absolute rewards
    """

    def __init__(self, store: LightningStore, config: Optional[Dict] = None):
        super().__init__(store, config)

        app_config = get_config()
        self.batch_size = config.get('batch_size', app_config.agent_lightning.batch_size)
        self.exploration_rate = config.get('exploration_rate', app_config.agent_lightning.exploration_rate)

        # Track pattern performance
        self.pattern_scores: Dict[str, List[float]] = defaultdict(list)
        self.strategy_scores: Dict[str, List[float]] = defaultdict(list)

        logger.info(f"GRPO initialized with batch_size={self.batch_size}")

    def compute_update(self, traces: List[Trace]) -> Optional[PolicyUpdate]:
        """
        Compute update using group relative optimization.

        Args:
            traces: Batch of traces

        Returns:
            PolicyUpdate with optimized prompt strategy
        """
        if len(traces) < 2:
            logger.warning("Need at least 2 traces for GRPO update")
            return None

        # Extract rewards and metadata
        rewards = []
        patterns_used = []
        prompts = []

        for trace in traces:
            if trace.reward is None:
                continue

            rewards.append(trace.reward)

            # Extract patterns from spans
            pattern_list = []
            prompt_text = ""

            for span in trace.spans:
                if span.span_type == "prompt":
                    prompt_text = span.data.get("prompt", "")

                if span.span_type == "patterns_checked":
                    pattern_list = span.data.get("patterns", [])

            patterns_used.append(pattern_list)
            prompts.append(prompt_text)

        if len(rewards) < 2:
            return None

        # Normalize rewards for comparison
        normalized_rewards = self.normalize_rewards(rewards)

        # Compute pattern scores
        pattern_performance = self._compute_pattern_scores(
            patterns_used,
            normalized_rewards
        )

        # Compute optimal strategy
        optimal_strategy = self._compute_optimal_strategy(
            pattern_performance,
            normalized_rewards
        )

        # Generate policy update
        update = PolicyUpdate(
            resource_type="prompt_strategy",
            content=optimal_strategy['strategy_description'],
            expected_improvement=optimal_strategy['expected_improvement'],
            confidence=optimal_strategy['confidence'],
            metadata={
                'pattern_rankings': pattern_performance,
                'batch_size': len(traces),
                'mean_reward': float(np.mean(rewards)),
                'std_reward': float(np.std(rewards))
            }
        )

        logger.info(
            f"GRPO update computed: expected improvement {update.expected_improvement:.3f}, "
            f"confidence {update.confidence:.2%}"
        )

        return update

    def _compute_pattern_scores(
        self,
        patterns_per_trace: List[List[str]],
        rewards: np.ndarray
    ) -> Dict[str, float]:
        """
        Compute relative scores for each pattern.

        Patterns that appear in higher-reward traces get higher scores.
        """
        pattern_scores = defaultdict(list)

        for patterns, reward in zip(patterns_per_trace, rewards):
            for pattern_id in patterns:
                pattern_scores[pattern_id].append(reward)

        # Average score for each pattern
        pattern_avg_scores = {
            pattern_id: float(np.mean(scores))
            for pattern_id, scores in pattern_scores.items()
        }

        # Update global tracking
        for pattern_id, score in pattern_avg_scores.items():
            self.pattern_scores[pattern_id].append(score)

        return pattern_avg_scores

    def _compute_optimal_strategy(
        self,
        pattern_performance: Dict[str, float],
        rewards: np.ndarray
    ) -> Dict[str, Any]:
        """
        Compute optimal prompt strategy based on pattern performance.
        """
        if not pattern_performance:
            return {
                'strategy_description': "default",
                'expected_improvement': 0.0,
                'confidence': 0.0,
                'top_patterns': []
            }

        # Rank patterns by performance
        ranked_patterns = sorted(
            pattern_performance.items(),
            key=lambda x: x[1],
            reverse=True
        )

        # Top patterns
        top_k = min(5, len(ranked_patterns))
        top_patterns = ranked_patterns[:top_k]

        # Expected improvement (based on top pattern scores vs mean)
        mean_reward = float(np.mean(rewards))
        top_scores = [score for _, score in top_patterns]
        expected_improvement = float(np.mean(top_scores)) - mean_reward

        # Confidence (based on variance)
        confidence = 1.0 - min(1.0, float(np.std(rewards)) / (abs(mean_reward) + 1e-8))

        strategy = {
            'strategy_description': f"prioritize_patterns_{','.join([p[0] for p in top_patterns[:3]])}",
            'expected_improvement': expected_improvement,
            'confidence': max(0.0, min(1.0, confidence)),
            'top_patterns': [
                {'pattern_id': pid, 'score': float(score)}
                for pid, score in top_patterns
            ],
            'exploration_rate': self.exploration_rate
        }

        return strategy

    def get_pattern_recommendations(
        self,
        min_observations: int = 5
    ) -> List[Tuple[str, float]]:
        """
        Get pattern recommendations based on historical performance.

        Args:
            min_observations: Minimum observations before recommending

        Returns:
            List of (pattern_id, average_score) tuples, sorted by score
        """
        recommendations = []

        for pattern_id, scores in self.pattern_scores.items():
            if len(scores) >= min_observations:
                avg_score = float(np.mean(scores))
                recommendations.append((pattern_id, avg_score))

        recommendations.sort(key=lambda x: x[1], reverse=True)
        return recommendations


class PromptOptimizer:
    """
    Optimizes prompt templates using evolutionary strategies.

    Tries different prompt variations and keeps the best performing ones.
    """

    def __init__(self, store: LightningStore):
        self.store = store
        self.prompt_versions: List[Dict] = []

        logger.info("PromptOptimizer initialized")

    def generate_variations(
        self,
        base_prompt: str,
        num_variations: int = 3
    ) -> List[str]:
        """
        Generate prompt variations for testing.

        Args:
            base_prompt: Base prompt template
            num_variations: Number of variations to generate

        Returns:
            List of prompt variations
        """
        variations = [base_prompt]  # Include original

        # Variation strategies
        # 1. More concise
        concise = base_prompt.replace(
            "Analyze this code for security vulnerabilities",
            "Check for security issues"
        )
        variations.append(concise)

        # 2. More detailed
        detailed = base_prompt.replace(
            "vulnerabilities",
            "vulnerabilities, paying special attention to input validation and data flow"
        )
        variations.append(detailed)

        # 3. Different ordering (if we have sections)
        # For now, just return the variations we have
        return variations[:num_variations]

    def select_best_prompt(
        self,
        prompt_results: List[Tuple[str, float]]
    ) -> str:
        """
        Select best performing prompt.

        Args:
            prompt_results: List of (prompt, reward) tuples

        Returns:
            Best prompt
        """
        if not prompt_results:
            return ""

        best_prompt, best_reward = max(prompt_results, key=lambda x: x[1])

        logger.info(f"Selected best prompt with reward {best_reward:.2f}")

        return best_prompt


if __name__ == "__main__":
    # Test GRPO
    from src.utils.logging_config import setup_logging
    from src.rl.store import LightningStore, Trace, Span
    from datetime import datetime

    setup_logging()

    store = LightningStore()
    grpo = GRPO(store)

    # Create test traces
    test_traces = []
    for i in range(10):
        trace_id = f"test-trace-{i}"
        trace = Trace(
            trace_id=trace_id,
            agent_name="defender",
            episode_number=i,
            spans=[
                Span(
                    span_id=f"{trace_id}-span-0",
                    trace_id=trace_id,
                    span_type="patterns_checked",
                    timestamp=datetime.now(),
                    data={"patterns": [f"PATTERN-{i%3}", "PATTERN-SQL-001"]}
                )
            ],
            reward=10.0 + i * 2.0 + np.random.randn() * 3.0,
            created_at=datetime.now()
        )
        test_traces.append(trace)

    # Compute update
    update = grpo.compute_update(test_traces)

    if update:
        print(f"Policy Update:")
        print(f"  Strategy: {update.content}")
        print(f"  Expected improvement: {update.expected_improvement:.3f}")
        print(f"  Confidence: {update.confidence:.2%}")
        print(f"  Metadata: {update.metadata}")

    # Get recommendations
    recommendations = grpo.get_pattern_recommendations()
    print(f"\nPattern Recommendations:")
    for pattern_id, score in recommendations:
        print(f"  {pattern_id}: {score:.3f}")
