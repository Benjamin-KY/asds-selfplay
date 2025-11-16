"""
Benchmark evaluation framework for vulnerability detection.

Evaluates defender performance on real-world datasets like CVEFixes.
"""

import json
import time
from pathlib import Path
from typing import List, Dict, Optional, Tuple
from dataclasses import dataclass, asdict
from datetime import datetime
import logging

from src.datasets.cvefixes import CVEFixesLoader, VulnerabilityInstance
from src.agents.defender import DefenderAgent, Finding
from src.knowledge.graph import SecurityKnowledgeGraph

logger = logging.getLogger(__name__)


@dataclass
class BenchmarkResult:
    """Results from a single vulnerability detection"""
    sample_id: str  # CVE ID or sample identifier
    cwe_id: str
    language: str

    # Ground truth
    has_vulnerability: bool  # True if sample contains a vulnerability

    # Defender predictions
    findings: List[Finding]
    detected: bool  # True if defender found at least one vulnerability

    # Classification
    true_positive: bool
    false_positive: bool
    false_negative: bool
    true_negative: bool

    # Metadata
    detection_time: float  # Seconds
    confidence_scores: List[float]  # Confidence for each finding

    def to_dict(self) -> dict:
        """Convert to dictionary"""
        d = asdict(self)
        d['findings'] = [f.to_dict() for f in self.findings]
        return d


@dataclass
class BenchmarkSummary:
    """Summary statistics for benchmark evaluation"""

    # Dataset info
    total_samples: int
    vulnerable_samples: int
    clean_samples: int

    # Performance metrics
    true_positives: int
    false_positives: int
    false_negatives: int
    true_negatives: int

    precision: float
    recall: float
    f1_score: float
    accuracy: float

    # Timing
    total_time: float
    avg_time_per_sample: float

    # Additional metrics
    avg_confidence: float
    detection_rate: float  # % of vulnerabilities detected
    false_positive_rate: float  # % of clean code flagged

    # By CWE type
    by_cwe: Dict[str, Dict[str, int]]  # {cwe_id: {tp, fp, fn, tn}}

    # Timestamp
    timestamp: str

    def to_dict(self) -> dict:
        """Convert to dictionary"""
        return asdict(self)


class BenchmarkRunner:
    """
    Run benchmark evaluations on vulnerability datasets.

    Usage:
        runner = BenchmarkRunner(defender, kg)
        results = runner.run_cvefixes_benchmark(limit=100)
        runner.save_results(results, "results/benchmark_001.json")
    """

    def __init__(
        self,
        defender: DefenderAgent,
        kg: SecurityKnowledgeGraph,
        output_dir: str = "data/benchmarks"
    ):
        """
        Initialize benchmark runner.

        Args:
            defender: Defender agent to evaluate
            kg: Knowledge graph (for tracking patterns)
            output_dir: Directory to save results
        """
        self.defender = defender
        self.kg = kg
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def run_cvefixes_benchmark(
        self,
        db_path: str = "data/datasets/CVEfixes.db",
        language: Optional[str] = "python",
        limit: Optional[int] = 100,
        cwe_types: Optional[List[str]] = None,
        verbose: bool = True
    ) -> Tuple[List[BenchmarkResult], BenchmarkSummary]:
        """
        Run benchmark on CVEFixes dataset.

        Args:
            db_path: Path to CVEfixes.db
            language: Filter by language (e.g., "python")
            limit: Maximum samples to evaluate
            cwe_types: Filter by CWE types
            verbose: Print progress

        Returns:
            (results, summary) tuple
        """
        logger.info(f"Starting CVEFixes benchmark (language={language}, limit={limit})")

        # Load dataset
        loader = CVEFixesLoader(db_path)
        samples = loader.load_samples(
            language=language,
            cwe_types=cwe_types,
            limit=limit
        )

        if not samples:
            raise ValueError("No samples loaded from CVEFixes dataset")

        if verbose:
            print(f"\n{'='*80}")
            print(f"CVEFixes Benchmark Evaluation")
            print(f"{'='*80}")
            print(f"Samples: {len(samples)}")
            print(f"Language: {language or 'all'}")
            print(f"CWE filter: {cwe_types or 'all'}")
            print(f"\nEvaluating...\n")

        results = []
        start_time = time.time()

        for i, sample in enumerate(samples, 1):
            if verbose and i % 10 == 0:
                elapsed = time.time() - start_time
                rate = i / elapsed
                eta = (len(samples) - i) / rate if rate > 0 else 0
                print(f"  Progress: {i}/{len(samples)} ({i/len(samples)*100:.1f}%) | "
                      f"Rate: {rate:.1f} samples/s | ETA: {eta:.0f}s")

            result = self._evaluate_sample(sample)
            results.append(result)

        total_time = time.time() - start_time

        # Generate summary
        summary = self._generate_summary(results, total_time)

        if verbose:
            self._print_summary(summary)

        return results, summary

    def _evaluate_sample(self, sample: VulnerabilityInstance) -> BenchmarkResult:
        """
        Evaluate defender on a single vulnerability sample.

        Args:
            sample: Vulnerability instance from dataset

        Returns:
            BenchmarkResult with classification
        """
        start_time = time.time()

        # Run defender on VULNERABLE code
        findings = self.defender.analyze_code(
            code=sample.vulnerable_code,
            language=sample.programming_language
        )

        detection_time = time.time() - start_time

        # Classification
        has_vulnerability = True  # CVEFixes samples are all vulnerable
        detected = len(findings) > 0

        # True positive: vulnerability exists AND defender found it
        true_positive = has_vulnerability and detected

        # False negative: vulnerability exists BUT defender missed it
        false_negative = has_vulnerability and not detected

        # False positive: no vulnerability BUT defender flagged it
        # (Not applicable for CVEFixes vulnerable samples)
        false_positive = False

        # True negative: no vulnerability AND defender didn't flag it
        # (Not applicable for CVEFixes vulnerable samples)
        true_negative = False

        # Extract confidence scores
        confidence_scores = [f.confidence for f in findings]

        return BenchmarkResult(
            sample_id=sample.cve_id,
            cwe_id=sample.cwe_id,
            language=sample.programming_language,
            has_vulnerability=has_vulnerability,
            findings=findings,
            detected=detected,
            true_positive=true_positive,
            false_positive=false_positive,
            false_negative=false_negative,
            true_negative=true_negative,
            detection_time=detection_time,
            confidence_scores=confidence_scores
        )

    def _generate_summary(
        self,
        results: List[BenchmarkResult],
        total_time: float
    ) -> BenchmarkSummary:
        """Generate summary statistics from results"""

        # Count classifications
        tp = sum(1 for r in results if r.true_positive)
        fp = sum(1 for r in results if r.false_positive)
        fn = sum(1 for r in results if r.false_negative)
        tn = sum(1 for r in results if r.true_negative)

        # Calculate metrics
        precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0
        accuracy = (tp + tn) / len(results) if results else 0.0

        # Detection and FP rates
        vulnerable_count = sum(1 for r in results if r.has_vulnerability)
        clean_count = len(results) - vulnerable_count

        detection_rate = tp / vulnerable_count if vulnerable_count > 0 else 0.0
        false_positive_rate = fp / clean_count if clean_count > 0 else 0.0

        # Average confidence
        all_confidences = []
        for r in results:
            all_confidences.extend(r.confidence_scores)
        avg_confidence = sum(all_confidences) / len(all_confidences) if all_confidences else 0.0

        # By CWE type
        by_cwe = {}
        for r in results:
            if r.cwe_id not in by_cwe:
                by_cwe[r.cwe_id] = {'tp': 0, 'fp': 0, 'fn': 0, 'tn': 0}

            if r.true_positive:
                by_cwe[r.cwe_id]['tp'] += 1
            elif r.false_positive:
                by_cwe[r.cwe_id]['fp'] += 1
            elif r.false_negative:
                by_cwe[r.cwe_id]['fn'] += 1
            elif r.true_negative:
                by_cwe[r.cwe_id]['tn'] += 1

        return BenchmarkSummary(
            total_samples=len(results),
            vulnerable_samples=vulnerable_count,
            clean_samples=clean_count,
            true_positives=tp,
            false_positives=fp,
            false_negatives=fn,
            true_negatives=tn,
            precision=precision,
            recall=recall,
            f1_score=f1,
            accuracy=accuracy,
            total_time=total_time,
            avg_time_per_sample=total_time / len(results) if results else 0.0,
            avg_confidence=avg_confidence,
            detection_rate=detection_rate,
            false_positive_rate=false_positive_rate,
            by_cwe=by_cwe,
            timestamp=datetime.now().isoformat()
        )

    def _print_summary(self, summary: BenchmarkSummary):
        """Print summary to console"""
        print(f"\n{'='*80}")
        print("BENCHMARK RESULTS")
        print(f"{'='*80}")

        print(f"\n📊 Dataset:")
        print(f"  Total samples: {summary.total_samples}")
        print(f"  Vulnerable: {summary.vulnerable_samples}")
        print(f"  Clean: {summary.clean_samples}")

        print(f"\n✅ Classification:")
        print(f"  True Positives:  {summary.true_positives:4}")
        print(f"  False Positives: {summary.false_positives:4}")
        print(f"  False Negatives: {summary.false_negatives:4}")
        print(f"  True Negatives:  {summary.true_negatives:4}")

        print(f"\n📈 Performance Metrics:")
        print(f"  Precision: {summary.precision:.1%}")
        print(f"  Recall:    {summary.recall:.1%}")
        print(f"  F1 Score:  {summary.f1_score:.1%}")
        print(f"  Accuracy:  {summary.accuracy:.1%}")

        print(f"\n⚡ Detection Rates:")
        print(f"  Detection Rate: {summary.detection_rate:.1%} (vulnerabilities caught)")
        print(f"  False Positive Rate: {summary.false_positive_rate:.1%}")

        print(f"\n🎯 Confidence:")
        print(f"  Average Confidence: {summary.avg_confidence:.1%}")

        print(f"\n⏱️  Timing:")
        print(f"  Total Time: {summary.total_time:.1f}s")
        print(f"  Avg Time/Sample: {summary.avg_time_per_sample:.2f}s")

        # Top CWE types by volume
        print(f"\n🔍 Top CWE Types:")
        cwe_totals = [(cwe, sum(counts.values())) for cwe, counts in summary.by_cwe.items()]
        cwe_totals.sort(key=lambda x: x[1], reverse=True)

        for cwe, count in cwe_totals[:10]:
            stats = summary.by_cwe[cwe]
            cwe_recall = stats['tp'] / (stats['tp'] + stats['fn']) if (stats['tp'] + stats['fn']) > 0 else 0
            print(f"  {cwe:15} {count:3} samples | Recall: {cwe_recall:.1%}")

        print()

    def save_results(
        self,
        results: List[BenchmarkResult],
        summary: BenchmarkSummary,
        name: str = None
    ) -> str:
        """
        Save benchmark results to file.

        Args:
            results: List of benchmark results
            summary: Summary statistics
            name: Optional name for results file

        Returns:
            Path to saved file
        """
        if name is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            name = f"benchmark_{timestamp}.json"

        output_path = self.output_dir / name

        data = {
            "summary": summary.to_dict(),
            "results": [r.to_dict() for r in results]
        }

        with open(output_path, 'w') as f:
            json.dump(data, f, indent=2, default=str)

        logger.info(f"Saved benchmark results to {output_path}")
        print(f"💾 Results saved to: {output_path}")

        return str(output_path)

    def compare_with_baseline(
        self,
        current_summary: BenchmarkSummary,
        baseline_path: str
    ):
        """
        Compare current results with baseline.

        Args:
            current_summary: Current benchmark summary
            baseline_path: Path to baseline results JSON
        """
        with open(baseline_path) as f:
            baseline_data = json.load(f)

        baseline = baseline_data['summary']

        print(f"\n{'='*80}")
        print("COMPARISON WITH BASELINE")
        print(f"{'='*80}")

        metrics = [
            ('Precision', current_summary.precision, baseline['precision']),
            ('Recall', current_summary.recall, baseline['recall']),
            ('F1 Score', current_summary.f1_score, baseline['f1_score']),
            ('Detection Rate', current_summary.detection_rate, baseline['detection_rate']),
        ]

        for metric_name, current_val, baseline_val in metrics:
            diff = current_val - baseline_val
            pct_change = (diff / baseline_val * 100) if baseline_val > 0 else 0

            symbol = "📈" if diff > 0 else "📉" if diff < 0 else "➡️"

            print(f"{metric_name:20} {current_val:6.1%} vs {baseline_val:6.1%} "
                  f"| {symbol} {diff:+.1%} ({pct_change:+.1f}%)")

        print()
