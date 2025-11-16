"""
Knowledge Graph for Security Patterns

Tracks patterns and their effectiveness via RL feedback.
Uses in-context learning instead of model fine-tuning.
"""

import networkx as nx
import sqlite3
import json
from pathlib import Path
from typing import List, Dict, Optional, Set
from dataclasses import dataclass, asdict
from datetime import datetime
from enum import Enum


class PatternType(Enum):
    """Types of security patterns"""
    SQL_INJECTION = "sql_injection"
    XSS = "xss"
    COMMAND_INJECTION = "command_injection"
    PATH_TRAVERSAL = "path_traversal"
    INSECURE_DESERIALIZATION = "insecure_deserialization"
    AUTHENTICATION_BYPASS = "authentication_bypass"
    HARDCODED_SECRETS = "hardcoded_secrets"
    CSRF = "csrf"
    SSRF = "ssrf"
    XXE = "xxe"


@dataclass
class SecurityPattern:
    """Represents a learnable security pattern"""
    id: str
    name: str
    pattern_type: PatternType
    code_example: str
    language: str
    risk_level: str  # critical, high, medium, low
    cwe_id: Optional[str] = None

    # Learning metrics (updated via attacker feedback)
    observations: int = 0
    true_positives: int = 0  # Attacker confirmed vulnerability
    false_positives: int = 0  # Attacker couldn't exploit
    false_negatives: int = 0  # Attacker found but defender missed

    # Derived metrics
    @property
    def precision(self) -> float:
        """TP / (TP + FP)"""
        total = self.true_positives + self.false_positives
        return self.true_positives / total if total > 0 else 0.0

    @property
    def recall(self) -> float:
        """TP / (TP + FN)"""
        total = self.true_positives + self.false_negatives
        return self.true_positives / total if total > 0 else 0.0

    @property
    def f1_score(self) -> float:
        """Harmonic mean of precision and recall"""
        p = self.precision
        r = self.recall
        return 2 * (p * r) / (p + r) if (p + r) > 0 else 0.0

    @property
    def effectiveness(self) -> float:
        """Overall effectiveness score (0-1)"""
        # Use F1 if we have enough data, otherwise neutral
        if self.observations < 3:
            return 0.5  # Neutral for new patterns
        return self.f1_score

    def to_dict(self) -> dict:
        """Convert to dictionary for storage"""
        d = asdict(self)
        d['pattern_type'] = self.pattern_type.value
        return d


class SecurityKnowledgeGraph:
    """
    Graph-based knowledge store for security patterns.

    Learns from adversarial self-play:
    - Tracks which patterns actually detect vulnerabilities
    - Prunes ineffective patterns
    - Grows with novel discoveries
    """

    def __init__(self, db_path: str = "data/patterns/knowledge.db"):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)

        self.graph = nx.DiGraph()
        self.patterns: Dict[str, SecurityPattern] = {}

        self._init_database()
        self._load_patterns()
        self._init_base_knowledge()

    def _init_database(self):
        """Initialize SQLite database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS patterns (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                pattern_type TEXT NOT NULL,
                code_example TEXT NOT NULL,
                language TEXT NOT NULL,
                risk_level TEXT NOT NULL,
                cwe_id TEXT,
                observations INTEGER DEFAULT 0,
                true_positives INTEGER DEFAULT 0,
                false_positives INTEGER DEFAULT 0,
                false_negatives INTEGER DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS pattern_relationships (
                source_id TEXT NOT NULL,
                target_id TEXT NOT NULL,
                relationship_type TEXT NOT NULL,
                weight REAL DEFAULT 1.0,
                FOREIGN KEY (source_id) REFERENCES patterns(id),
                FOREIGN KEY (target_id) REFERENCES patterns(id),
                PRIMARY KEY (source_id, target_id, relationship_type)
            )
        """)

        conn.commit()
        conn.close()

    def _load_patterns(self):
        """Load patterns from database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute("SELECT * FROM patterns")
        rows = cursor.fetchall()

        for row in rows:
            pattern = SecurityPattern(
                id=row[0],
                name=row[1],
                pattern_type=PatternType(row[2]),
                code_example=row[3],
                language=row[4],
                risk_level=row[5],
                cwe_id=row[6],
                observations=row[7],
                true_positives=row[8],
                false_positives=row[9],
                false_negatives=row[10]
            )
            self.patterns[pattern.id] = pattern
            self._add_pattern_to_graph(pattern)

        conn.close()

    def _init_base_knowledge(self):
        """Initialize with fundamental security patterns"""
        if len(self.patterns) > 0:
            return  # Already initialized

        base_patterns = [
            SecurityPattern(
                id="PATTERN-SQL-001",
                name="String concatenation in SQL query",
                pattern_type=PatternType.SQL_INJECTION,
                code_example='query = f"SELECT * FROM users WHERE id={user_id}"',
                language="python",
                risk_level="critical",
                cwe_id="CWE-89"
            ),
            SecurityPattern(
                id="PATTERN-SQL-002",
                name="String formatting in SQL query",
                pattern_type=PatternType.SQL_INJECTION,
                code_example='query = "SELECT * FROM users WHERE name=\'%s\'" % username',
                language="python",
                risk_level="critical",
                cwe_id="CWE-89"
            ),
            SecurityPattern(
                id="PATTERN-XSS-001",
                name="innerHTML without sanitization",
                pattern_type=PatternType.XSS,
                code_example='element.innerHTML = user_input',
                language="javascript",
                risk_level="high",
                cwe_id="CWE-79"
            ),
            SecurityPattern(
                id="PATTERN-CMD-001",
                name="os.system with user input",
                pattern_type=PatternType.COMMAND_INJECTION,
                code_example='os.system(f"ping {host}")',
                language="python",
                risk_level="critical",
                cwe_id="CWE-78"
            ),
            SecurityPattern(
                id="PATTERN-CMD-002",
                name="subprocess.call with shell=True",
                pattern_type=PatternType.COMMAND_INJECTION,
                code_example='subprocess.call(f"ls {directory}", shell=True)',
                language="python",
                risk_level="critical",
                cwe_id="CWE-78"
            ),
            SecurityPattern(
                id="PATTERN-PATH-001",
                name="Path concatenation with user input",
                pattern_type=PatternType.PATH_TRAVERSAL,
                code_example='open(f"/uploads/{filename}")',
                language="python",
                risk_level="high",
                cwe_id="CWE-22"
            ),
            SecurityPattern(
                id="PATTERN-DESER-001",
                name="pickle.loads on untrusted data",
                pattern_type=PatternType.INSECURE_DESERIALIZATION,
                code_example='data = pickle.loads(request.data)',
                language="python",
                risk_level="critical",
                cwe_id="CWE-502"
            ),
            SecurityPattern(
                id="PATTERN-AUTH-001",
                name="Hardcoded credentials",
                pattern_type=PatternType.HARDCODED_SECRETS,
                code_example='password = "admin123"',
                language="python",
                risk_level="high",
                cwe_id="CWE-798"
            ),
        ]

        for pattern in base_patterns:
            self.add_pattern(pattern)

    def _add_pattern_to_graph(self, pattern: SecurityPattern):
        """Add pattern to NetworkX graph"""
        self.graph.add_node(
            pattern.id,
            node_type="pattern",
            **pattern.to_dict()
        )

        # Link to CWE if available
        if pattern.cwe_id:
            if not self.graph.has_node(pattern.cwe_id):
                self.graph.add_node(
                    pattern.cwe_id,
                    node_type="vulnerability",
                    name=pattern.cwe_id
                )
            self.graph.add_edge(
                pattern.id,
                pattern.cwe_id,
                edge_type="MANIFESTS_AS",
                weight=pattern.effectiveness
            )

    def add_pattern(self, pattern: SecurityPattern):
        """Add new pattern to knowledge graph"""
        self.patterns[pattern.id] = pattern
        self._add_pattern_to_graph(pattern)

        # Save to database
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute("""
            INSERT OR REPLACE INTO patterns
            (id, name, pattern_type, code_example, language, risk_level, cwe_id,
             observations, true_positives, false_positives, false_negatives, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            pattern.id, pattern.name, pattern.pattern_type.value,
            pattern.code_example, pattern.language, pattern.risk_level,
            pattern.cwe_id, pattern.observations, pattern.true_positives,
            pattern.false_positives, pattern.false_negatives,
            datetime.now().isoformat()
        ))

        conn.commit()
        conn.close()

    def update_pattern_effectiveness(
        self,
        pattern_id: str,
        is_true_positive: bool,
        is_false_negative: bool = False
    ):
        """
        Update pattern metrics based on attacker feedback.

        This is how the graph learns!

        Args:
            pattern_id: Pattern being evaluated
            is_true_positive: Attacker confirmed this was a real vulnerability
            is_false_negative: Attacker found vulnerability that defender missed
        """
        if pattern_id not in self.patterns:
            return

        pattern = self.patterns[pattern_id]
        pattern.observations += 1

        if is_true_positive:
            pattern.true_positives += 1
        elif is_false_negative:
            pattern.false_negatives += 1
        else:
            pattern.false_positives += 1

        # Update in graph
        self.graph.nodes[pattern_id].update(pattern.to_dict())

        # Update edge weight to CWE
        if pattern.cwe_id:
            self.graph.edges[pattern_id, pattern.cwe_id]["weight"] = pattern.effectiveness

        # Save to database
        self.add_pattern(pattern)

    def get_effective_patterns(
        self,
        min_effectiveness: float = 0.7,
        min_observations: int = 3,
        language: Optional[str] = None,
        limit: int = 10
    ) -> List[SecurityPattern]:
        """Get patterns with proven effectiveness"""
        effective = []

        for pattern in self.patterns.values():
            # Filter by language
            if language and pattern.language != language:
                continue

            # Need enough data
            if pattern.observations < min_observations:
                continue

            # High effectiveness threshold
            if pattern.effectiveness >= min_effectiveness:
                effective.append(pattern)

        # Sort by effectiveness descending
        effective.sort(key=lambda p: p.effectiveness, reverse=True)
        return effective[:limit]

    def get_ineffective_patterns(
        self,
        max_effectiveness: float = 0.3,
        min_observations: int = 10
    ) -> List[SecurityPattern]:
        """Get patterns with poor track record (high false positive rate)"""
        ineffective = []

        for pattern in self.patterns.values():
            if pattern.observations >= min_observations:
                if pattern.effectiveness <= max_effectiveness:
                    ineffective.append(pattern)

        return ineffective

    def get_recent_patterns(self, limit: int = 5) -> List[SecurityPattern]:
        """Get recently added patterns"""
        # For now, return patterns with few observations
        # In production, would track creation timestamps
        recent = sorted(
            self.patterns.values(),
            key=lambda p: p.observations
        )
        return recent[:limit]

    def prune_ineffective_patterns(
        self,
        max_effectiveness: float = 0.2,
        min_observations: int = 20
    ) -> int:
        """
        Remove patterns that consistently produce false positives.

        Returns number of patterns pruned.
        """
        to_prune = []

        for pattern_id, pattern in self.patterns.items():
            if pattern.observations >= min_observations:
                if pattern.effectiveness <= max_effectiveness:
                    to_prune.append(pattern_id)

        # Remove from graph and database
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        for pattern_id in to_prune:
            self.graph.remove_node(pattern_id)
            del self.patterns[pattern_id]

            cursor.execute("DELETE FROM patterns WHERE id = ?", (pattern_id,))

        conn.commit()
        conn.close()

        return len(to_prune)

    def get_stats(self) -> Dict:
        """Get knowledge graph statistics"""
        if not self.patterns:
            return {
                "total_patterns": 0,
                "total_observations": 0,
                "avg_effectiveness": 0.0
            }

        return {
            "total_patterns": len(self.patterns),
            "total_observations": sum(p.observations for p in self.patterns.values()),
            "avg_effectiveness": sum(p.effectiveness for p in self.patterns.values()) / len(self.patterns),
            "patterns_by_type": {
                pt.value: len([p for p in self.patterns.values() if p.pattern_type == pt])
                for pt in PatternType
            },
            "high_effectiveness_patterns": len(self.get_effective_patterns()),
            "low_effectiveness_patterns": len(self.get_ineffective_patterns())
        }

    def export_for_visualization(self, output_path: str = "data/graph_viz.json"):
        """Export graph for visualization"""
        nodes = []
        edges = []

        for node_id, data in self.graph.nodes(data=True):
            nodes.append({
                "id": node_id,
                "type": data.get("node_type", "unknown"),
                **{k: v for k, v in data.items() if k != "node_type"}
            })

        for source, target, data in self.graph.edges(data=True):
            edges.append({
                "source": source,
                "target": target,
                "type": data.get("edge_type", "unknown"),
                "weight": data.get("weight", 1.0)
            })

        output = {
            "nodes": nodes,
            "edges": edges,
            "stats": self.get_stats()
        }

        Path(output_path).parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, 'w') as f:
            json.dump(output, f, indent=2)


if __name__ == "__main__":
    # Test the knowledge graph
    kg = SecurityKnowledgeGraph()

    print("Knowledge Graph Initialized")
    print(f"Stats: {json.dumps(kg.get_stats(), indent=2)}")

    print("\nEffective patterns:")
    for p in kg.get_effective_patterns():
        print(f"  - {p.name}: {p.effectiveness:.2%}")

    # Simulate learning
    print("\nSimulating feedback...")
    kg.update_pattern_effectiveness("PATTERN-SQL-001", is_true_positive=True)
    kg.update_pattern_effectiveness("PATTERN-SQL-001", is_true_positive=True)
    kg.update_pattern_effectiveness("PATTERN-SQL-001", is_false_negative=False)

    pattern = kg.patterns["PATTERN-SQL-001"]
    print(f"PATTERN-SQL-001 after feedback:")
    print(f"  Effectiveness: {pattern.effectiveness:.2%}")
    print(f"  Precision: {pattern.precision:.2%}")
    print(f"  Recall: {pattern.recall:.2%}")
