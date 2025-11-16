#!/usr/bin/env python3
"""
Run benchmark evaluation on CVEFixes dataset.

Usage:
    python scripts/run_benchmark.py --limit 100 --language python
    python scripts/run_benchmark.py --limit 1000 --output baseline_1000.json
    python scripts/run_benchmark.py --compare-with data/benchmarks/baseline.json
"""

import argparse
import sys
import os
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.knowledge.graph import SecurityKnowledgeGraph
from src.patterns.library import initialize_pattern_library
from src.agents.defender import DefenderAgent
from src.evaluation.benchmark import BenchmarkRunner
from src.utils.config import get_config
from src.utils.logging_config import setup_logging


def main():
    parser = argparse.ArgumentParser(
        description="Run benchmark evaluation on CVEFixes dataset"
    )
    parser.add_argument(
        "--db-path",
        type=str,
        default="data/datasets/CVEfixes.db",
        help="Path to CVEfixes.db database"
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=100,
        help="Number of samples to evaluate (default: 100)"
    )
    parser.add_argument(
        "--language",
        type=str,
        default="python",
        help="Programming language to filter (default: python)"
    )
    parser.add_argument(
        "--cwe-types",
        type=str,
        nargs="+",
        help="Filter by CWE types (e.g., CWE-89 CWE-79)"
    )
    parser.add_argument(
        "--output",
        type=str,
        help="Output filename for results (default: auto-generated)"
    )
    parser.add_argument(
        "--compare-with",
        type=str,
        help="Compare results with baseline file"
    )
    parser.add_argument(
        "--no-patterns",
        action="store_true",
        help="Skip loading pattern library (use only base patterns)"
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Show verbose output"
    )

    args = parser.parse_args()

    # Setup logging
    setup_logging()

    # Check API key
    if not os.getenv("ANTHROPIC_API_KEY"):
        print("Error: ANTHROPIC_API_KEY not set")
        print("Set it with: export ANTHROPIC_API_KEY='your-key'")
        sys.exit(1)

    # Check database exists
    if not Path(args.db_path).exists():
        print(f"Error: CVEfixes database not found at {args.db_path}")
        print("Download it with: python scripts/download_cvefixes.py")
        sys.exit(1)

    print("="*80)
    print("CVEFixes Benchmark Evaluation")
    print("="*80)
    print(f"Database: {args.db_path}")
    print(f"Limit: {args.limit} samples")
    print(f"Language: {args.language}")
    if args.cwe_types:
        print(f"CWE filter: {', '.join(args.cwe_types)}")
    print()

    # Initialize components
    print("Initializing knowledge graph and defender...")
    kg = SecurityKnowledgeGraph()

    if not args.no_patterns:
        pattern_count = initialize_pattern_library(kg)
        print(f"✓ Loaded {pattern_count} vulnerability patterns")
    else:
        print("⚠ Using base patterns only (--no-patterns)")

    config = get_config()
    defender = DefenderAgent(kg)

    print("✓ Defender agent ready")
    print()

    # Create benchmark runner
    runner = BenchmarkRunner(defender, kg)

    # Run benchmark
    try:
        results, summary = runner.run_cvefixes_benchmark(
            db_path=args.db_path,
            language=args.language,
            limit=args.limit,
            cwe_types=args.cwe_types,
            verbose=True
        )

        # Save results
        output_path = runner.save_results(results, summary, name=args.output)

        # Compare with baseline if requested
        if args.compare_with:
            runner.compare_with_baseline(summary, args.compare_with)

        print("\n✓ Benchmark complete!")
        print(f"\nKey Results:")
        print(f"  F1 Score: {summary.f1_score:.1%}")
        print(f"  Precision: {summary.precision:.1%}")
        print(f"  Recall: {summary.recall:.1%}")
        print(f"  Detection Rate: {summary.detection_rate:.1%}")

    except FileNotFoundError as e:
        print(f"\nError: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"\nUnexpected error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
