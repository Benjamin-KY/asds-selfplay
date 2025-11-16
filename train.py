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
from src.agents.defender import DefenderAgent
from src.agents.attacker import AttackerAgent
from src.core.self_play import SelfPlayTrainer
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
    print()

    # Initialize components
    print("Initializing components...")
    kg = SecurityKnowledgeGraph()
    defender = DefenderAgent(kg)
    attacker = AttackerAgent()
    trainer = SelfPlayTrainer(kg, defender, attacker)

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
    print()


if __name__ == "__main__":
    main()
