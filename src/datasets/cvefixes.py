"""
CVEFixes Dataset Loader

Loads vulnerability data from the CVEFixes database (Zenodo DOI: 10.5281/zenodo.4476563).
Provides access to 12,107 real-world vulnerability fixes across 272 CWE types.
"""

import sqlite3
import pandas as pd
from pathlib import Path
from typing import List, Dict, Optional, Tuple
from dataclasses import dataclass
import logging

logger = logging.getLogger(__name__)


@dataclass
class VulnerabilityInstance:
    """Single vulnerability instance from CVEFixes"""
    cve_id: str
    cwe_id: str
    programming_language: str
    vulnerable_code: str
    fixed_code: str
    method_name: str
    file_name: str
    commit_hash: str
    repository: str
    severity: Optional[str] = None


class CVEFixesLoader:
    """
    Loader for CVEFixes vulnerability dataset.

    Usage:
        loader = CVEFixesLoader("data/datasets/CVEfixes.db")
        samples = loader.load_samples(language="python", limit=100)

        for sample in samples:
            print(f"CVE: {sample.cve_id}, CWE: {sample.cwe_id}")
            print(f"Vulnerable code: {sample.vulnerable_code[:100]}")
    """

    def __init__(self, db_path: str = "data/datasets/CVEfixes.db"):
        """
        Initialize loader.

        Args:
            db_path: Path to CVEfixes.db SQLite database
        """
        self.db_path = Path(db_path)

        if not self.db_path.exists():
            logger.warning(
                f"CVEFixes database not found at {db_path}. "
                f"Download from: https://zenodo.org/records/4476563"
            )

    def _connect(self) -> sqlite3.Connection:
        """Create database connection"""
        if not self.db_path.exists():
            raise FileNotFoundError(
                f"CVEFixes database not found at {self.db_path}. "
                f"Download from: https://zenodo.org/records/4476563"
            )
        return sqlite3.connect(self.db_path)

    def load_samples(
        self,
        language: Optional[str] = None,
        cwe_types: Optional[List[str]] = None,
        limit: Optional[int] = None,
        min_code_length: int = 10,
        max_code_length: int = 10000
    ) -> List[VulnerabilityInstance]:
        """
        Load vulnerability samples from dataset.

        Args:
            language: Filter by programming language (e.g., "Python", "JavaScript")
            cwe_types: Filter by CWE IDs (e.g., ["CWE-89", "CWE-79"])
            limit: Maximum number of samples to load
            min_code_length: Minimum code length in characters
            max_code_length: Maximum code length in characters

        Returns:
            List of VulnerabilityInstance objects
        """
        conn = self._connect()

        # Build query
        query = """
        SELECT
            cve.cve_id,
            cwe.cwe_id,
            fc.programming_language,
            mc.code as fixed_code,
            mc.before_change as vulnerable_code,
            mc.name as method_name,
            fc.filename,
            fc.hash as commit_hash,
            repo.url as repository
        FROM method_change mc
        JOIN file_change fc ON mc.file_change_id = fc.file_change_id
        JOIN fixes f ON fc.hash = f.hash
        JOIN cve ON f.cve_id = cve.cve_id
        LEFT JOIN cve_cwe cc ON cve.cve_id = cc.cve_id
        LEFT JOIN cwe ON cc.cwe_id = cwe.cwe_id
        LEFT JOIN repository repo ON fc.hash IN (
            SELECT hash FROM commits WHERE repo_id = repo.repo_id
        )
        WHERE mc.before_change IS NOT NULL
        AND mc.code IS NOT NULL
        """

        # Add filters
        conditions = []
        params = []

        if language:
            conditions.append("LOWER(fc.programming_language) = LOWER(?)")
            params.append(language)

        if cwe_types:
            placeholders = ",".join("?" * len(cwe_types))
            conditions.append(f"cwe.cwe_id IN ({placeholders})")
            params.extend(cwe_types)

        # Code length filters
        conditions.append("LENGTH(mc.before_change) >= ?")
        conditions.append("LENGTH(mc.before_change) <= ?")
        params.extend([min_code_length, max_code_length])

        if conditions:
            query += " AND " + " AND ".join(conditions)

        if limit:
            query += f" LIMIT {limit}"

        logger.info(f"Loading CVEFixes samples (language={language}, limit={limit})")

        try:
            df = pd.read_sql_query(query, conn, params=params)
            conn.close()

            logger.info(f"Loaded {len(df)} vulnerability samples")

            # Convert to VulnerabilityInstance objects
            samples = []
            for _, row in df.iterrows():
                sample = VulnerabilityInstance(
                    cve_id=row['cve_id'],
                    cwe_id=row['cwe_id'] if pd.notna(row['cwe_id']) else "Unknown",
                    programming_language=row['programming_language'],
                    vulnerable_code=row['vulnerable_code'],
                    fixed_code=row['fixed_code'],
                    method_name=row['method_name'],
                    file_name=row['filename'],
                    commit_hash=row['commit_hash'],
                    repository=row['repository'] if pd.notna(row['repository']) else "Unknown"
                )
                samples.append(sample)

            return samples

        except Exception as e:
            conn.close()
            logger.error(f"Error loading CVEFixes samples: {e}")
            raise

    def get_statistics(self) -> Dict:
        """
        Get dataset statistics.

        Returns:
            Dictionary with counts by language, CWE, etc.
        """
        conn = self._connect()

        stats = {}

        try:
            # Total vulnerabilities
            total_query = "SELECT COUNT(DISTINCT cve_id) as count FROM cve"
            stats['total_cves'] = pd.read_sql_query(total_query, conn)['count'].iloc[0]

            # By programming language
            lang_query = """
            SELECT programming_language, COUNT(*) as count
            FROM file_change
            WHERE programming_language IS NOT NULL
            GROUP BY programming_language
            ORDER BY count DESC
            """
            stats['by_language'] = pd.read_sql_query(lang_query, conn).to_dict('records')

            # By CWE type
            cwe_query = """
            SELECT cwe.cwe_id, cwe.cwe_name, COUNT(*) as count
            FROM cve_cwe cc
            JOIN cwe ON cc.cwe_id = cwe.cwe_id
            GROUP BY cwe.cwe_id, cwe.cwe_name
            ORDER BY count DESC
            LIMIT 20
            """
            stats['top_cwes'] = pd.read_sql_query(cwe_query, conn).to_dict('records')

            # Total methods with before/after
            method_query = """
            SELECT COUNT(*) as count
            FROM method_change
            WHERE before_change IS NOT NULL AND code IS NOT NULL
            """
            stats['total_methods_with_fixes'] = pd.read_sql_query(method_query, conn)['count'].iloc[0]

            conn.close()
            return stats

        except Exception as e:
            conn.close()
            logger.error(f"Error getting statistics: {e}")
            raise

    def load_for_training(
        self,
        train_split: float = 0.8,
        language: Optional[str] = None,
        seed: int = 42
    ) -> Tuple[List[VulnerabilityInstance], List[VulnerabilityInstance]]:
        """
        Load dataset split into train/test sets.

        Args:
            train_split: Fraction of data for training (e.g., 0.8 = 80%)
            language: Filter by programming language
            seed: Random seed for reproducible splits

        Returns:
            (train_samples, test_samples) tuple
        """
        all_samples = self.load_samples(language=language)

        # Shuffle deterministically
        import random
        random.seed(seed)
        random.shuffle(all_samples)

        # Split
        split_idx = int(len(all_samples) * train_split)
        train_samples = all_samples[:split_idx]
        test_samples = all_samples[split_idx:]

        logger.info(f"Split dataset: {len(train_samples)} train, {len(test_samples)} test")

        return train_samples, test_samples

    def export_to_examples_format(
        self,
        samples: List[VulnerabilityInstance],
        output_path: str = "examples/cvefixes_samples.py"
    ):
        """
        Export samples to the examples format used by train.py.

        Args:
            samples: List of vulnerability instances
            output_path: Where to save the Python file
        """
        output = f"""\"\"\"
CVEFixes vulnerability samples (auto-generated).

Generated from CVEFixes dataset (v1.0.8).
Source: https://zenodo.org/records/4476563
\"\"\"

CVEFIXES_SAMPLES = [
"""

        for sample in samples:
            output += f"""    {{
        "name": "{sample.cve_id} - {sample.cwe_id}",
        "language": "{sample.programming_language.lower()}",
        "code": '''
{sample.vulnerable_code}
''',
        "expected_vulnerabilities": ["{sample.cwe_id}"],
        "cve_id": "{sample.cve_id}",
        "fixed_code": '''
{sample.fixed_code}
'''
    }},
"""

        output += """]

def get_cvefixes_samples():
    \"\"\"Get all CVEFixes samples\"\"\"
    return CVEFIXES_SAMPLES
"""

        with open(output_path, 'w') as f:
            f.write(output)

        logger.info(f"Exported {len(samples)} samples to {output_path}")
