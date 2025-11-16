#!/usr/bin/env python3
"""
ASDS Self-Play Training CLI

Run self-play training episodes.
"""

import argparse
import os
import sys
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent))

from src.knowledge.graph import SecurityKnowledgeGraph
from src.patterns.library import initialize_pattern_library
from src.agents.defender import DefenderAgent
from src.agents.attacker import AttackerAgent
from src.core.self_play import SelfPlayTrainer
from src.rl.store import LightningStore
from src.rl.trainer import Trainer
from src.utils.config import get_config
from src.utils.logging_config import setup_logging
from examples.vulnerable_samples import get_vulnerable_only, get_all_samples


def main():
    parser = argparse.ArgumentParser(
        description="ASDS Self-Play Training"
    )
    parser.add_argument(
        "--episodes",
        type=int,
        default=10,
        help="Number of training episodes to run"
    )
    parser.add_argument(
        "--dataset",
        choices=["vulnerable", "all"],
        default="vulnerable",
        help="Which dataset to use"
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Show detailed output"
    )

    args = parser.parse_args()

    # Setup logging
    setup_logging()

    # Load config
    config = get_config()

    # Check API key
    if not os.getenv("ANTHROPIC_API_KEY"):
        print("Error: ANTHROPIC_API_KEY not set")
        print("Set it with: export ANTHROPIC_API_KEY='your-key'")
        sys.exit(1)

    print("="*80)
    print("ASDS Self-Play Training")
    print("="*80)
    print(f"Episodes: {args.episodes}")
    print(f"Dataset: {args.dataset}")
    print(f"RL Enabled: {config.agent_lightning.enabled}")
    print()

    # Initialize components
    print("Initializing components...")
    kg = SecurityKnowledgeGraph()

    # Initialize pattern library (52+ vulnerability patterns)
    pattern_count = initialize_pattern_library(kg)
    print(f"Loaded {pattern_count} vulnerability patterns into knowledge graph")

    # Initialize RL store and trainer if enabled
    rl_store = None
    rl_trainer = None

    if config.agent_lightning.enabled:
        print("Initializing RL infrastructure...")
        rl_store = LightningStore()
        rl_trainer = Trainer(
            store=rl_store,
            algorithm=config.agent_lightning.algorithm
        )
        print(f"  RL Algorithm: {config.agent_lightning.algorithm}")
        print(f"  Batch Size: {config.agent_lightning.batch_size}")
        print(f"  Update Frequency: every {config.agent_lightning.update_frequency} episodes")

    defender = DefenderAgent(kg, rl_store=rl_store)
    attacker = AttackerAgent()
    trainer = SelfPlayTrainer(
        kg,
        defender,
        attacker,
        rl_store=rl_store,
        rl_trainer=rl_trainer
    )

    # Get dataset
    if args.dataset == "vulnerable":
        samples = get_vulnerable_only()
    else:
        samples = get_all_samples()

    print(f"Loaded {len(samples)} code samples")
    print()

    # Run training episodes
    for episode_num in range(args.episodes):
        # Select sample (cycle through if more episodes than samples)
        sample = samples[episode_num % len(samples)]

        print(f"\nTraining on: {sample['name']}")

        # Run episode
        episode = trainer.train_episode(
            code_sample=sample['code'],
            language=sample['language']
        )

        if not args.verbose:
            # Show compact summary
            print(f"  Reward: {episode.reward:.1f} | "
                  f"TP: {episode.true_positives} | "
                  f"FP: {episode.false_positives} | "
                  f"FN: {episode.false_negatives}")

    # Show final progress
    print("\n" + "="*80)
    print("TRAINING COMPLETE")
    print("="*80)

    progress = trainer.get_learning_progress()

    print(f"\nEpisodes completed: {progress['total_episodes']}")
    print(f"Early average reward: {progress['early_avg_reward']:.2f}")
    print(f"Recent average reward: {progress['recent_avg_reward']:.2f}")
    print(f"Improvement: {progress['improvement']:.2f} ({progress['improvement_pct']:.1f}%)")

    print(f"\nRecent performance:")
    print(f"  True positives: {progress['recent_true_positives']:.1f}")
    print(f"  False positives: {progress['recent_false_positives']:.1f}")

    print(f"\nKnowledge graph stats:")
    kg_stats = progress['knowledge_graph_stats']
    print(f"  Total patterns: {kg_stats['total_patterns']}")
    print(f"  Total observations: {kg_stats['total_observations']}")
    print(f"  Average effectiveness: {kg_stats['avg_effectiveness']:.1%}")

    print("\nEpisode data saved to: data/episodes/")

    # Show RL training summary if enabled
    if config.agent_lightning.enabled and rl_trainer:
        print("\n" + "="*80)
        print("RL TRAINING SUMMARY")
        print("="*80)

        rl_summary = rl_trainer.get_training_summary()
        print(f"\nUpdates applied: {rl_summary['updates_applied']}")
        print(f"Best performance: {rl_summary['best_performance']:.3f}")

        if rl_summary['pattern_recommendations']:
            print(f"\nTop pattern recommendations:")
            for i, (pattern_id, score) in enumerate(rl_summary['pattern_recommendations'][:5], 1):
                print(f"  {i}. {pattern_id}: {score:.3f}")

        print(f"\nRL store stats:")
        store_stats = rl_summary['store_stats']
        print(f"  Total traces: {store_stats.get('total_traces', 0)}")
        print(f"  Average reward: {store_stats.get('average_reward', 0):.2f}")

    print()


if __name__ == "__main__":
    main()
