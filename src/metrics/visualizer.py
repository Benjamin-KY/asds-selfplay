"""
Metrics visualization for ASDS Self-Play training.

Generates plots and dashboards to track learning progress.
"""

import json
import matplotlib.pyplot as plt
import seaborn as sns
import pandas as pd
from pathlib import Path
from typing import List, Dict, Optional
import numpy as np

from src.utils.logging_config import get_logger

logger = get_logger(__name__)

# Set style
sns.set_theme(style="whitegrid")


class TrainingVisualizer:
    """
    Visualize training progress and metrics.
    """

    def __init__(self, episodes_dir: str = "data/episodes"):
        self.episodes_dir = Path(episodes_dir)
        logger.info(f"TrainingVisualizer initialized: {episodes_dir}")

    def load_episodes(self) -> List[Dict]:
        """Load all episode data from JSON files"""
        episodes = []

        for episode_file in sorted(self.episodes_dir.glob("episode_*.json")):
            try:
                with open(episode_file, 'r') as f:
                    data = json.load(f)
                    episodes.append(data)
            except Exception as e:
                logger.warning(f"Failed to load {episode_file}: {e}")

        logger.info(f"Loaded {len(episodes)} episodes")
        return episodes

    def plot_reward_over_time(
        self,
        episodes: Optional[List[Dict]] = None,
        save_path: Optional[str] = None
    ):
        """Plot reward progression over episodes"""
        if episodes is None:
            episodes = self.load_episodes()

        if not episodes:
            logger.warning("No episodes to plot")
            return

        episode_numbers = [ep['episode_number'] for ep in episodes]
        rewards = [ep['reward'] for ep in episodes]

        # Calculate moving average
        window = min(10, len(rewards) // 4) if len(rewards) > 3 else 1
        if window > 1:
            moving_avg = pd.Series(rewards).rolling(window=window, min_periods=1).mean()
        else:
            moving_avg = rewards

        plt.figure(figsize=(12, 6))
        plt.plot(episode_numbers, rewards, alpha=0.3, label='Episode Reward')
        plt.plot(episode_numbers, moving_avg, linewidth=2, label=f'Moving Avg (window={window})')
        plt.xlabel('Episode')
        plt.ylabel('Reward')
        plt.title('Training Reward Over Time')
        plt.legend()
        plt.grid(True, alpha=0.3)

        if save_path:
            plt.savefig(save_path, dpi=150, bbox_inches='tight')
            logger.info(f"Saved reward plot to {save_path}")
        else:
            plt.show()

        plt.close()

    def plot_metrics_over_time(
        self,
        episodes: Optional[List[Dict]] = None,
        save_path: Optional[str] = None
    ):
        """Plot TP/FP/FN metrics over time"""
        if episodes is None:
            episodes = self.load_episodes()

        if not episodes:
            return

        episode_numbers = [ep['episode_number'] for ep in episodes]
        true_positives = [ep['true_positives'] for ep in episodes]
        false_positives = [ep['false_positives'] for ep in episodes]
        false_negatives = [ep['false_negatives'] for ep in episodes]

        fig, axes = plt.subplots(3, 1, figsize=(12, 10), sharex=True)

        # True Positives
        axes[0].plot(episode_numbers, true_positives, 'g-', label='True Positives')
        axes[0].set_ylabel('True Positives')
        axes[0].legend()
        axes[0].grid(True, alpha=0.3)

        # False Positives
        axes[1].plot(episode_numbers, false_positives, 'r-', label='False Positives')
        axes[1].set_ylabel('False Positives')
        axes[1].legend()
        axes[1].grid(True, alpha=0.3)

        # False Negatives
        axes[2].plot(episode_numbers, false_negatives, 'orange', label='False Negatives')
        axes[2].set_ylabel('False Negatives')
        axes[2].set_xlabel('Episode')
        axes[2].legend()
        axes[2].grid(True, alpha=0.3)

        plt.suptitle('Detection Metrics Over Time')

        if save_path:
            plt.savefig(save_path, dpi=150, bbox_inches='tight')
            logger.info(f"Saved metrics plot to {save_path}")
        else:
            plt.show()

        plt.close()

    def plot_precision_recall(
        self,
        episodes: Optional[List[Dict]] = None,
        save_path: Optional[str] = None
    ):
        """Plot precision and recall over time"""
        if episodes is None:
            episodes = self.load_episodes()

        if not episodes:
            return

        episode_numbers = []
        precisions = []
        recalls = []

        for ep in episodes:
            tp = ep['true_positives']
            fp = ep['false_positives']
            fn = ep['false_negatives']

            # Calculate precision and recall
            precision = tp / (tp + fp) if (tp + fp) > 0 else 0
            recall = tp / (tp + fn) if (tp + fn) > 0 else 0

            episode_numbers.append(ep['episode_number'])
            precisions.append(precision)
            recalls.append(recall)

        plt.figure(figsize=(12, 6))
        plt.plot(episode_numbers, precisions, label='Precision', linewidth=2)
        plt.plot(episode_numbers, recalls, label='Recall', linewidth=2)
        plt.xlabel('Episode')
        plt.ylabel('Score')
        plt.title('Precision and Recall Over Time')
        plt.legend()
        plt.grid(True, alpha=0.3)
        plt.ylim(0, 1.1)

        if save_path:
            plt.savefig(save_path, dpi=150, bbox_inches='tight')
            logger.info(f"Saved precision/recall plot to {save_path}")
        else:
            plt.show()

        plt.close()

    def generate_dashboard(
        self,
        output_dir: str = "data/visualizations"
    ):
        """Generate all visualizations"""
        output_path = Path(output_dir)
        output_path.mkdir(parents=True, exist_ok=True)

        episodes = self.load_episodes()

        if not episodes:
            logger.warning("No episodes found, skipping visualization")
            return

        logger.info(f"Generating visualizations for {len(episodes)} episodes")

        # Generate plots
        self.plot_reward_over_time(
            episodes,
            save_path=str(output_path / "reward_over_time.png")
        )

        self.plot_metrics_over_time(
            episodes,
            save_path=str(output_path / "metrics_over_time.png")
        )

        self.plot_precision_recall(
            episodes,
            save_path=str(output_path / "precision_recall.png")
        )

        logger.info(f"Visualizations saved to {output_path}")

        # Generate summary stats
        self._generate_summary_stats(episodes, output_path)

    def _generate_summary_stats(self, episodes: List[Dict], output_path: Path):
        """Generate summary statistics"""
        rewards = [ep['reward'] for ep in episodes]
        tps = [ep['true_positives'] for ep in episodes]
        fps = [ep['false_positives'] for ep in episodes]
        fns = [ep['false_negatives'] for ep in episodes]

        stats = {
            'total_episodes': len(episodes),
            'reward_stats': {
                'mean': float(np.mean(rewards)),
                'std': float(np.std(rewards)),
                'min': float(np.min(rewards)),
                'max': float(np.max(rewards)),
            },
            'recent_performance': {
                'window': min(10, len(episodes)),
                'avg_reward': float(np.mean(rewards[-10:])),
                'avg_tp': float(np.mean(tps[-10:])),
                'avg_fp': float(np.mean(fps[-10:])),
                'avg_fn': float(np.mean(fns[-10:])),
            }
        }

        stats_file = output_path / "training_stats.json"
        with open(stats_file, 'w') as f:
            json.dump(stats, indent=2, fp=f)

        logger.info(f"Summary stats saved to {stats_file}")


if __name__ == "__main__":
    # Test visualization
    from src.utils.logging_config import setup_logging
    setup_logging()

    visualizer = TrainingVisualizer()
    visualizer.generate_dashboard()
    print("Visualizations generated!")
