"""
Tests for benchmark evaluation framework.
"""

import pytest
import json
import tempfile
from pathlib import Path
from unittest.mock import Mock, MagicMock, patch

from src.evaluation.benchmark import (
    BenchmarkRunner,
    BenchmarkResult,
    BenchmarkSummary
)
from src.datasets.cvefixes import VulnerabilityInstance
from src.agents.defender import Finding
from src.knowledge.graph import SecurityKnowledgeGraph, SecurityPattern, PatternType


@pytest.fixture
def temp_dir():
    """Temporary directory for test files"""
    with tempfile.TemporaryDirectory() as tmpdir:
        yield Path(tmpdir)


@pytest.fixture
def mock_defender():
    """Mock defender agent"""
    defender = Mock()
    return defender


@pytest.fixture
def mock_kg():
    """Mock knowledge graph"""
    return Mock(spec=SecurityKnowledgeGraph)


@pytest.fixture
def sample_finding():
    """Sample finding for testing"""
    return Finding(
        id="finding-001",
        type="SQL Injection",
        pattern_id="PATTERN-SQL-001",
        cwe_id="CWE-89",
        severity="critical",
        location="line 10",
        code_snippet='query = f"SELECT * FROM users WHERE id={user_id}"',
        explanation="Unsafe string concatenation in SQL query",
        suggested_fix="Use parameterized queries",
        confidence=0.85
    )


@pytest.fixture
def sample_vulnerability():
    """Sample vulnerability instance"""
    return VulnerabilityInstance(
        cve_id="CVE-2024-1234",
        cwe_id="CWE-89",
        programming_language="Python",
        vulnerable_code='query = f"SELECT * FROM users WHERE id={user_id}"',
        fixed_code='query = "SELECT * FROM users WHERE id=?"',
        method_name="get_user",
        file_name="database.py",
        commit_hash="abc123",
        repository="https://github.com/example/repo"
    )


class TestBenchmarkResult:
    """Test BenchmarkResult dataclass"""

    def test_benchmark_result_creation(self, sample_finding):
        """Test creating a benchmark result"""
        result = BenchmarkResult(
            sample_id="CVE-2024-1234",
            cwe_id="CWE-89",
            language="python",
            has_vulnerability=True,
            findings=[sample_finding],
            detected=True,
            true_positive=True,
            false_positive=False,
            false_negative=False,
            true_negative=False,
            detection_time=2.5,
            confidence_scores=[0.85]
        )

        assert result.sample_id == "CVE-2024-1234"
        assert result.cwe_id == "CWE-89"
        assert result.true_positive is True
        assert result.false_negative is False
        assert len(result.findings) == 1
        assert result.confidence_scores == [0.85]

    def test_benchmark_result_to_dict(self, sample_finding):
        """Test converting result to dictionary"""
        result = BenchmarkResult(
            sample_id="CVE-2024-1234",
            cwe_id="CWE-89",
            language="python",
            has_vulnerability=True,
            findings=[sample_finding],
            detected=True,
            true_positive=True,
            false_positive=False,
            false_negative=False,
            true_negative=False,
            detection_time=2.5,
            confidence_scores=[0.85]
        )

        result_dict = result.to_dict()

        assert result_dict['sample_id'] == "CVE-2024-1234"
        assert result_dict['true_positive'] is True
        assert isinstance(result_dict['findings'], list)
        assert len(result_dict['findings']) == 1


class TestBenchmarkSummary:
    """Test BenchmarkSummary dataclass"""

    def test_summary_metrics_calculation(self):
        """Test that summary calculates metrics correctly"""
        summary = BenchmarkSummary(
            total_samples=100,
            vulnerable_samples=100,
            clean_samples=0,
            true_positives=70,
            false_positives=5,
            false_negatives=30,
            true_negatives=0,
            precision=70 / (70 + 5),
            recall=70 / (70 + 30),
            f1_score=2 * (70/75 * 70/100) / (70/75 + 70/100),
            accuracy=70 / 100,
            total_time=250.0,
            avg_time_per_sample=2.5,
            avg_confidence=0.75,
            detection_rate=0.70,
            false_positive_rate=0.0,
            by_cwe={},
            timestamp="2024-01-01T00:00:00"
        )

        assert summary.total_samples == 100
        assert summary.true_positives == 70
        assert summary.false_negatives == 30
        assert summary.precision == pytest.approx(70/75)
        assert summary.recall == pytest.approx(0.70)

    def test_summary_to_dict(self):
        """Test converting summary to dictionary"""
        summary = BenchmarkSummary(
            total_samples=10,
            vulnerable_samples=10,
            clean_samples=0,
            true_positives=7,
            false_positives=0,
            false_negatives=3,
            true_negatives=0,
            precision=1.0,
            recall=0.7,
            f1_score=0.82,
            accuracy=0.7,
            total_time=25.0,
            avg_time_per_sample=2.5,
            avg_confidence=0.8,
            detection_rate=0.7,
            false_positive_rate=0.0,
            by_cwe={"CWE-89": {"tp": 7, "fp": 0, "fn": 3, "tn": 0}},
            timestamp="2024-01-01T00:00:00"
        )

        summary_dict = summary.to_dict()

        assert summary_dict['total_samples'] == 10
        assert summary_dict['precision'] == 1.0
        assert "CWE-89" in summary_dict['by_cwe']


class TestBenchmarkRunner:
    """Test BenchmarkRunner class"""

    def test_runner_initialization(self, mock_defender, mock_kg, temp_dir):
        """Test creating a benchmark runner"""
        runner = BenchmarkRunner(mock_defender, mock_kg, output_dir=str(temp_dir))

        assert runner.defender == mock_defender
        assert runner.kg == mock_kg
        assert runner.output_dir.exists()

    def test_evaluate_sample_detected(
        self,
        mock_defender,
        mock_kg,
        sample_vulnerability,
        sample_finding,
        temp_dir
    ):
        """Test evaluating a sample where vulnerability is detected"""
        # Setup mock defender to return a finding
        mock_defender.analyze_code.return_value = [sample_finding]

        runner = BenchmarkRunner(mock_defender, mock_kg, output_dir=str(temp_dir))
        result = runner._evaluate_sample(sample_vulnerability)

        # Verify result
        assert result.sample_id == "CVE-2024-1234"
        assert result.cwe_id == "CWE-89"
        assert result.has_vulnerability is True
        assert result.detected is True
        assert result.true_positive is True
        assert result.false_negative is False
        assert len(result.findings) == 1
        assert result.detection_time > 0

    def test_evaluate_sample_missed(
        self,
        mock_defender,
        mock_kg,
        sample_vulnerability,
        temp_dir
    ):
        """Test evaluating a sample where vulnerability is missed"""
        # Setup mock defender to return no findings
        mock_defender.analyze_code.return_value = []

        runner = BenchmarkRunner(mock_defender, mock_kg, output_dir=str(temp_dir))
        result = runner._evaluate_sample(sample_vulnerability)

        # Verify result
        assert result.detected is False
        assert result.true_positive is False
        assert result.false_negative is True
        assert len(result.findings) == 0

    def test_generate_summary(
        self,
        mock_defender,
        mock_kg,
        sample_finding,
        temp_dir
    ):
        """Test generating summary from results"""
        runner = BenchmarkRunner(mock_defender, mock_kg, output_dir=str(temp_dir))

        # Create mock results
        results = [
            BenchmarkResult(
                sample_id=f"CVE-2024-{i}",
                cwe_id="CWE-89",
                language="python",
                has_vulnerability=True,
                findings=[sample_finding] if i < 7 else [],
                detected=i < 7,
                true_positive=i < 7,
                false_positive=False,
                false_negative=i >= 7,
                true_negative=False,
                detection_time=2.0,
                confidence_scores=[0.85] if i < 7 else []
            )
            for i in range(10)
        ]

        summary = runner._generate_summary(results, total_time=20.0)

        # Verify summary
        assert summary.total_samples == 10
        assert summary.true_positives == 7
        assert summary.false_negatives == 3
        assert summary.precision == pytest.approx(1.0)  # No FP
        assert summary.recall == pytest.approx(0.7)  # 7/10
        assert summary.total_time == 20.0
        assert summary.avg_time_per_sample == 2.0

    def test_save_results(
        self,
        mock_defender,
        mock_kg,
        sample_finding,
        temp_dir
    ):
        """Test saving benchmark results to file"""
        runner = BenchmarkRunner(mock_defender, mock_kg, output_dir=str(temp_dir))

        # Create sample results
        results = [
            BenchmarkResult(
                sample_id="CVE-2024-1234",
                cwe_id="CWE-89",
                language="python",
                has_vulnerability=True,
                findings=[sample_finding],
                detected=True,
                true_positive=True,
                false_positive=False,
                false_negative=False,
                true_negative=False,
                detection_time=2.0,
                confidence_scores=[0.85]
            )
        ]

        summary = BenchmarkSummary(
            total_samples=1,
            vulnerable_samples=1,
            clean_samples=0,
            true_positives=1,
            false_positives=0,
            false_negatives=0,
            true_negatives=0,
            precision=1.0,
            recall=1.0,
            f1_score=1.0,
            accuracy=1.0,
            total_time=2.0,
            avg_time_per_sample=2.0,
            avg_confidence=0.85,
            detection_rate=1.0,
            false_positive_rate=0.0,
            by_cwe={"CWE-89": {"tp": 1, "fp": 0, "fn": 0, "tn": 0}},
            timestamp="2024-01-01T00:00:00"
        )

        # Save results
        output_path = runner.save_results(results, summary, name="test_results.json")

        # Verify file was created
        assert Path(output_path).exists()

        # Verify content
        with open(output_path) as f:
            data = json.load(f)

        assert 'summary' in data
        assert 'results' in data
        assert data['summary']['total_samples'] == 1
        assert len(data['results']) == 1

    def test_compare_with_baseline(
        self,
        mock_defender,
        mock_kg,
        temp_dir,
        capsys
    ):
        """Test comparing results with baseline"""
        runner = BenchmarkRunner(mock_defender, mock_kg, output_dir=str(temp_dir))

        # Create baseline file
        baseline_data = {
            "summary": {
                "precision": 0.6,
                "recall": 0.5,
                "f1_score": 0.55,
                "detection_rate": 0.5
            }
        }

        baseline_path = temp_dir / "baseline.json"
        with open(baseline_path, 'w') as f:
            json.dump(baseline_data, f)

        # Create current summary with better metrics
        current_summary = BenchmarkSummary(
            total_samples=100,
            vulnerable_samples=100,
            clean_samples=0,
            true_positives=70,
            false_positives=5,
            false_negatives=30,
            true_negatives=0,
            precision=0.7,
            recall=0.7,
            f1_score=0.7,
            accuracy=0.7,
            total_time=200.0,
            avg_time_per_sample=2.0,
            avg_confidence=0.75,
            detection_rate=0.7,
            false_positive_rate=0.05,
            by_cwe={},
            timestamp="2024-01-01T00:00:00"
        )

        # Compare
        runner.compare_with_baseline(current_summary, str(baseline_path))

        # Capture output
        captured = capsys.readouterr()

        # Verify comparison was printed
        assert "COMPARISON WITH BASELINE" in captured.out
        assert "Precision" in captured.out
        assert "Recall" in captured.out
        assert "70.0%" in captured.out  # Current value (formatted)
        assert "60.0%" in captured.out or "50.0%" in captured.out  # Baseline value


class TestBenchmarkIntegration:
    """Integration tests for benchmark system"""

    @patch('src.evaluation.benchmark.CVEFixesLoader')
    def test_run_cvefixes_benchmark_integration(
        self,
        mock_loader_class,
        mock_defender,
        mock_kg,
        sample_vulnerability,
        sample_finding,
        temp_dir
    ):
        """Test running a full benchmark (mocked)"""
        # Setup mock loader
        mock_loader = Mock()
        mock_loader.load_samples.return_value = [sample_vulnerability] * 5
        mock_loader_class.return_value = mock_loader

        # Setup mock defender
        mock_defender.analyze_code.return_value = [sample_finding]

        runner = BenchmarkRunner(mock_defender, mock_kg, output_dir=str(temp_dir))

        # Run benchmark
        results, summary = runner.run_cvefixes_benchmark(
            db_path="dummy.db",
            language="python",
            limit=5,
            verbose=False
        )

        # Verify results
        assert len(results) == 5
        assert summary.total_samples == 5
        assert summary.true_positives == 5  # All detected
        assert summary.false_negatives == 0
        assert summary.precision == 1.0
        assert summary.recall == 1.0

    def test_by_cwe_breakdown(
        self,
        mock_defender,
        mock_kg,
        sample_finding,
        temp_dir
    ):
        """Test CWE breakdown in summary"""
        runner = BenchmarkRunner(mock_defender, mock_kg, output_dir=str(temp_dir))

        # Create results with different CWE types
        results = [
            BenchmarkResult(
                sample_id=f"CVE-{i}",
                cwe_id="CWE-89" if i < 5 else "CWE-79",
                language="python",
                has_vulnerability=True,
                findings=[sample_finding] if i % 2 == 0 else [],
                detected=i % 2 == 0,
                true_positive=i % 2 == 0,
                false_positive=False,
                false_negative=i % 2 != 0,
                true_negative=False,
                detection_time=2.0,
                confidence_scores=[0.85] if i % 2 == 0 else []
            )
            for i in range(10)
        ]

        summary = runner._generate_summary(results, total_time=20.0)

        # Verify CWE breakdown
        assert "CWE-89" in summary.by_cwe
        assert "CWE-79" in summary.by_cwe

        # CWE-89: 5 samples (indices 0-4), detected at 0,2,4 = 3 TP, 2 FN
        assert summary.by_cwe["CWE-89"]["tp"] == 3
        assert summary.by_cwe["CWE-89"]["fn"] == 2

        # CWE-79: 5 samples (indices 5-9), detected at 6,8 = 2 TP, 3 FN
        assert summary.by_cwe["CWE-79"]["tp"] == 2
        assert summary.by_cwe["CWE-79"]["fn"] == 3
