#!/usr/bin/env python3
"""
Explore CVEFixes dataset statistics.

Usage:
    python scripts/explore_cvefixes.py
    python scripts/explore_cvefixes.py --export-samples 100 --language python
"""

import argparse
import sys
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.datasets import CVEFixesLoader


def print_statistics(loader: CVEFixesLoader):
    """Print dataset statistics"""
    print("="*80)
    print("CVEFixes Dataset Statistics")
    print("="*80)

    stats = loader.get_statistics()

    print(f"\nTotal CVEs: {stats['total_cves']:,}")
    print(f"Total methods with fixes: {stats['total_methods_with_fixes']:,}")

    print(f"\nTop 10 Programming Languages:")
    print("-" * 40)
    for i, lang in enumerate(stats['by_language'][:10], 1):
        print(f"  {i:2}. {lang['programming_language']:20} {lang['count']:>8,}")

    print(f"\nTop 20 CWE Types:")
    print("-" * 60)
    for i, cwe in enumerate(stats['top_cwes'][:20], 1):
        cwe_name = cwe['cwe_name'][:40] if cwe['cwe_name'] else "Unknown"
        print(f"  {i:2}. {cwe['cwe_id']:12} {cwe_name:40} {cwe['count']:>6,}")


def show_sample(loader: CVEFixesLoader, language: str = None):
    """Show a sample vulnerability"""
    print("\n" + "="*80)
    print("Sample Vulnerability")
    print("="*80)

    samples = loader.load_samples(language=language, limit=1)

    if not samples:
        print("No samples found!")
        return

    sample = samples[0]

    print(f"\nCVE ID: {sample.cve_id}")
    print(f"CWE ID: {sample.cwe_id}")
    print(f"Language: {sample.programming_language}")
    print(f"Repository: {sample.repository}")
    print(f"Method: {sample.method_name}")
    print(f"File: {sample.file_name}")

    print(f"\n--- VULNERABLE CODE ---")
    print(sample.vulnerable_code[:500])
    if len(sample.vulnerable_code) > 500:
        print(f"... ({len(sample.vulnerable_code) - 500} more characters)")

    print(f"\n--- FIXED CODE ---")
    print(sample.fixed_code[:500])
    if len(sample.fixed_code) > 500:
        print(f"... ({len(sample.fixed_code) - 500} more characters)")


def export_samples(loader: CVEFixesLoader, count: int, language: str = None):
    """Export samples for training"""
    print(f"\nExporting {count} samples (language={language})...")

    samples = loader.load_samples(language=language, limit=count)

    if not samples:
        print("No samples found!")
        return

    output_path = f"examples/cvefixes_samples_{language or 'all'}_{count}.py"
    loader.export_to_examples_format(samples, output_path)

    print(f"✓ Exported {len(samples)} samples to {output_path}")


def main():
    parser = argparse.ArgumentParser(
        description="Explore CVEFixes dataset"
    )
    parser.add_argument(
        "--db-path",
        type=str,
        default="data/datasets/CVEfixes.db",
        help="Path to CVEfixes.db (default: data/datasets/CVEfixes.db)"
    )
    parser.add_argument(
        "--language",
        type=str,
        help="Filter by programming language (e.g., python, javascript)"
    )
    parser.add_argument(
        "--stats",
        action="store_true",
        help="Show dataset statistics"
    )
    parser.add_argument(
        "--sample",
        action="store_true",
        help="Show a random sample vulnerability"
    )
    parser.add_argument(
        "--export-samples",
        type=int,
        metavar="N",
        help="Export N samples to examples/ directory"
    )

    args = parser.parse_args()

    # Create loader
    loader = CVEFixesLoader(args.db_path)

    # Run requested operations
    if args.stats or (not args.sample and not args.export_samples):
        # Default to showing stats if nothing else specified
        print_statistics(loader)

    if args.sample:
        show_sample(loader, language=args.language)

    if args.export_samples:
        export_samples(loader, args.export_samples, language=args.language)


if __name__ == "__main__":
    main()
