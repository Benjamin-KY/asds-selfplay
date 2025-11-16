"""
RL Trainer for Agent Lightning integration.

Orchestrates the training loop, manages data collection, and applies
policy updates.
"""

import json
from pathlib import Path
from typing import Optional, Dict, Any, List
from datetime import datetime

from src.rl.store import LightningStore
from src.rl.algorithms import PolicyOptimizer, GRPO, PromptOptimizer
from src.utils.config import get_config
from src.utils.logging_config import get_logger

logger = get_logger(__name__)


class Trainer:
    """
    RL Trainer for optimizing agent behavior.

    Manages:
    - Data collection from store
    - Algorithm execution
    - Resource updates
    - Checkpointing
    """

    def __init__(
        self,
        store: LightningStore,
        algorithm: str = "GRPO",
        config: Optional[Dict] = None
    ):
        self.store = store
        self.algorithm_name = algorithm

        # Load config
        app_config = get_config()
        self.config = config or {}
        self.batch_size = self.config.get('batch_size', app_config.agent_lightning.batch_size)
        self.update_frequency = self.config.get('update_frequency', app_config.agent_lightning.update_frequency)
        self.save_frequency = self.config.get('save_frequency', app_config.agent_lightning.save_frequency)

        # Initialize algorithm
        self.optimizer = self._init_algorithm(algorithm)
        self.prompt_optimizer = PromptOptimizer(store)

        # Training state
        self.updates_applied = 0
        self.episodes_trained = 0
        self.best_performance = float('-inf')

        # Checkpoints
        self.checkpoint_dir = Path(app_config.training.checkpoints_dir)
        self.checkpoint_dir.mkdir(parents=True, exist_ok=True)

        logger.info(f"Trainer initialized with algorithm={algorithm}")

    def _init_algorithm(self, algorithm: str) -> PolicyOptimizer:
        """Initialize RL algorithm"""
        if algorithm.upper() == "GRPO":
            return GRPO(self.store, self.config)
        else:
            logger.warning(f"Unknown algorithm {algorithm}, defaulting to GRPO")
            return GRPO(self.store, self.config)

    def train_step(self, episode_number: int) -> Optional[Dict[str, Any]]:
        """
        Execute one training step.

        Args:
            episode_number: Current episode number

        Returns:
            Training metrics or None if not enough data
        """
        # Check if we should train at this step
        if episode_number % self.update_frequency != 0:
            return None

        logger.info(f"Training step at episode {episode_number}")

        # Get training data
        traces = self.store.get_training_data(
            batch_size=self.batch_size,
            agent_name="defender"  # Focus on defender for now
        )

        if len(traces) < 2:
            logger.warning(f"Insufficient traces for training: {len(traces)}")
            return None

        # Compute policy update
        update = self.optimizer.compute_update(traces)

        if update is None:
            logger.warning("No policy update computed")
            return None

        # Apply update
        self._apply_update(update)

        # Update state
        self.updates_applied += 1
        self.episodes_trained = episode_number

        # Track performance
        current_performance = update.expected_improvement
        if current_performance > self.best_performance:
            self.best_performance = current_performance
            logger.info(f"New best performance: {self.best_performance:.3f}")

        # Save checkpoint if needed
        if self.updates_applied % self.save_frequency == 0:
            self.save_checkpoint()

        metrics = {
            'episode': episode_number,
            'updates_applied': self.updates_applied,
            'expected_improvement': update.expected_improvement,
            'confidence': update.confidence,
            'best_performance': self.best_performance,
            'traces_used': len(traces)
        }

        logger.info(f"Training step complete: {metrics}")

        return metrics

    def _apply_update(self, update):
        """Apply policy update to store"""
        # Save updated resource
        version = self.updates_applied + 1

        self.store.save_resource(
            resource_type=update.resource_type,
            content=update.content,
            version=version,
            performance_metrics={
                'expected_improvement': update.expected_improvement,
                'confidence': update.confidence,
                **update.metadata
            }
        )

        logger.info(f"Applied update {version}: {update.resource_type}")

    def get_current_strategy(self) -> Optional[Dict]:
        """
        Get current best strategy.

        Returns:
            Latest resource or None
        """
        return self.store.get_latest_resource("prompt_strategy")

    def get_pattern_recommendations(self) -> List[tuple]:
        """
        Get pattern recommendations from optimizer.

        Returns:
            List of (pattern_id, score) tuples
        """
        if isinstance(self.optimizer, GRPO):
            return self.optimizer.get_pattern_recommendations()
        return []

    def save_checkpoint(self):
        """Save training checkpoint"""
        checkpoint = {
            'algorithm': self.algorithm_name,
            'updates_applied': self.updates_applied,
            'episodes_trained': self.episodes_trained,
            'best_performance': self.best_performance,
            'config': self.config,
            'timestamp': datetime.now().isoformat(),
            'pattern_recommendations': self.get_pattern_recommendations()
        }

        checkpoint_file = self.checkpoint_dir / f"checkpoint_{self.updates_applied:04d}.json"

        with open(checkpoint_file, 'w') as f:
            json.dump(checkpoint, f, indent=2)

        logger.info(f"Saved checkpoint: {checkpoint_file}")

        # Also save as 'latest'
        latest_file = self.checkpoint_dir / "checkpoint_latest.json"
        with open(latest_file, 'w') as f:
            json.dump(checkpoint, f, indent=2)

    def load_checkpoint(self, checkpoint_path: Optional[str] = None):
        """
        Load training checkpoint.

        Args:
            checkpoint_path: Path to checkpoint file. If None, loads latest.
        """
        if checkpoint_path is None:
            checkpoint_path = self.checkpoint_dir / "checkpoint_latest.json"
        else:
            checkpoint_path = Path(checkpoint_path)

        if not checkpoint_path.exists():
            logger.warning(f"Checkpoint not found: {checkpoint_path}")
            return

        with open(checkpoint_path, 'r') as f:
            checkpoint = json.load(f)

        self.updates_applied = checkpoint['updates_applied']
        self.episodes_trained = checkpoint['episodes_trained']
        self.best_performance = checkpoint['best_performance']

        logger.info(f"Loaded checkpoint from {checkpoint_path}")
        logger.info(f"  Updates: {self.updates_applied}, Episodes: {self.episodes_trained}")

    def get_training_summary(self) -> Dict[str, Any]:
        """
        Get summary of training progress.

        Returns:
            Training summary dict
        """
        store_stats = self.store.get_statistics()

        return {
            'updates_applied': self.updates_applied,
            'episodes_trained': self.episodes_trained,
            'best_performance': self.best_performance,
            'algorithm': self.algorithm_name,
            'store_stats': store_stats,
            'pattern_recommendations': self.get_pattern_recommendations()[:10]
        }


if __name__ == "__main__":
    # Test trainer
    from src.utils.logging_config import setup_logging
    from src.rl.store import LightningStore

    setup_logging()

    store = LightningStore()
    trainer = Trainer(store, algorithm="GRPO")

    # Simulate training
    print("Training Summary:")
    summary = trainer.get_training_summary()
    print(json.dumps(summary, indent=2))

    # Save checkpoint
    trainer.save_checkpoint()
    print("\nCheckpoint saved")

    # Load checkpoint
    trainer.load_checkpoint()
    print("Checkpoint loaded")
