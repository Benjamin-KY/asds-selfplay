"""
LightningStore: Central hub for traces and rewards.

Compatible with Agent Lightning architecture but implemented
specifically for ASDS Self-Play.
"""

import json
import sqlite3
from pathlib import Path
from typing import List, Dict, Optional, Any
from dataclasses import dataclass, asdict
from datetime import datetime
from collections import defaultdict

from src.utils.config import get_config
from src.utils.logging_config import get_logger

logger = get_logger(__name__)


@dataclass
class Span:
    """
    A single event in a trace (prompt, tool call, observation).
    """
    span_id: str
    trace_id: str
    span_type: str  # "prompt", "tool_call", "observation", "reward"
    timestamp: datetime
    data: Dict[str, Any]

    def to_dict(self) -> dict:
        return {
            **asdict(self),
            'timestamp': self.timestamp.isoformat(),
            'data': self.data
        }


@dataclass
class Trace:
    """
    A complete execution trace (one analysis episode).
    """
    trace_id: str
    agent_name: str  # "defender" or "attacker"
    episode_number: int
    spans: List[Span]
    reward: Optional[float] = None
    metadata: Optional[Dict[str, Any]] = None
    created_at: Optional[datetime] = None

    def to_dict(self) -> dict:
        return {
            'trace_id': self.trace_id,
            'agent_name': self.agent_name,
            'episode_number': self.episode_number,
            'spans': [s.to_dict() for s in self.spans],
            'reward': self.reward,
            'metadata': self.metadata,
            'created_at': self.created_at.isoformat() if self.created_at else None
        }


class LightningStore:
    """
    Central store for traces, rewards, and learned resources.

    Provides:
    - Trace storage and retrieval
    - Reward emission and tracking
    - Resource versioning (prompts, strategies)
    - Training data for RL algorithms
    """

    def __init__(self, db_path: Optional[str] = None):
        if db_path is None:
            config = get_config()
            db_dir = Path(config.training.checkpoints_dir)
            db_dir.mkdir(parents=True, exist_ok=True)
            db_path = str(db_dir / "lightning_store.db")

        self.db_path = db_path
        self._init_database()

        # In-memory cache for current episode
        self._active_traces: Dict[str, Trace] = {}
        self._span_buffer: Dict[str, List[Span]] = defaultdict(list)

        logger.info(f"LightningStore initialized at {db_path}")

    def _init_database(self):
        """Initialize SQLite database for traces"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS traces (
                trace_id TEXT PRIMARY KEY,
                agent_name TEXT NOT NULL,
                episode_number INTEGER NOT NULL,
                reward REAL,
                metadata TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS spans (
                span_id TEXT PRIMARY KEY,
                trace_id TEXT NOT NULL,
                span_type TEXT NOT NULL,
                timestamp TIMESTAMP NOT NULL,
                data TEXT NOT NULL,
                FOREIGN KEY (trace_id) REFERENCES traces(trace_id)
            )
        """)

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS resources (
                resource_id TEXT PRIMARY KEY,
                resource_type TEXT NOT NULL,
                version INTEGER NOT NULL,
                content TEXT NOT NULL,
                performance_metrics TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)

        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_traces_episode
            ON traces(episode_number)
        """)

        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_spans_trace
            ON spans(trace_id)
        """)

        conn.commit()
        conn.close()

    def start_trace(
        self,
        agent_name: str,
        episode_number: int,
        metadata: Optional[Dict] = None
    ) -> str:
        """
        Start a new trace.

        Args:
            agent_name: Name of the agent ("defender", "attacker")
            episode_number: Current episode number
            metadata: Optional metadata

        Returns:
            Trace ID
        """
        trace_id = f"{agent_name}-ep{episode_number}-{datetime.now().timestamp()}"

        trace = Trace(
            trace_id=trace_id,
            agent_name=agent_name,
            episode_number=episode_number,
            spans=[],
            metadata=metadata,
            created_at=datetime.now()
        )

        self._active_traces[trace_id] = trace
        logger.debug(f"Started trace {trace_id}")

        return trace_id

    def emit_span(
        self,
        trace_id: str,
        span_type: str,
        data: Dict[str, Any]
    ) -> str:
        """
        Emit a span (event) to a trace.

        Args:
            trace_id: Trace to add span to
            span_type: Type of span ("prompt", "tool_call", "observation")
            data: Span data

        Returns:
            Span ID
        """
        span_id = f"{trace_id}-span-{len(self._span_buffer[trace_id])}"

        span = Span(
            span_id=span_id,
            trace_id=trace_id,
            span_type=span_type,
            timestamp=datetime.now(),
            data=data
        )

        self._span_buffer[trace_id].append(span)

        if trace_id in self._active_traces:
            self._active_traces[trace_id].spans.append(span)

        logger.debug(f"Emitted {span_type} span to {trace_id}")

        return span_id

    def emit_reward(
        self,
        trace_id: str,
        reward: float,
        metadata: Optional[Dict] = None
    ):
        """
        Emit reward for a trace.

        Args:
            trace_id: Trace ID
            reward: Reward value
            metadata: Optional metadata about the reward
        """
        if trace_id in self._active_traces:
            self._active_traces[trace_id].reward = reward

        # Also store as a span
        self.emit_span(
            trace_id=trace_id,
            span_type="reward",
            data={"reward": reward, "metadata": metadata}
        )

        logger.debug(f"Emitted reward {reward:.2f} for {trace_id}")

    def end_trace(self, trace_id: str):
        """
        End a trace and persist to database.

        Args:
            trace_id: Trace ID to end
        """
        if trace_id not in self._active_traces:
            logger.warning(f"Trace {trace_id} not found in active traces")
            return

        trace = self._active_traces[trace_id]

        # Persist to database
        self._save_trace(trace)

        # Clean up
        del self._active_traces[trace_id]
        if trace_id in self._span_buffer:
            del self._span_buffer[trace_id]

        logger.debug(f"Ended and persisted trace {trace_id}")

    def _save_trace(self, trace: Trace):
        """Save trace to database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        # Save trace
        cursor.execute("""
            INSERT OR REPLACE INTO traces
            (trace_id, agent_name, episode_number, reward, metadata, created_at)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (
            trace.trace_id,
            trace.agent_name,
            trace.episode_number,
            trace.reward,
            json.dumps(trace.metadata) if trace.metadata else None,
            trace.created_at.isoformat() if trace.created_at else None
        ))

        # Save spans
        for span in trace.spans:
            cursor.execute("""
                INSERT OR REPLACE INTO spans
                (span_id, trace_id, span_type, timestamp, data)
                VALUES (?, ?, ?, ?, ?)
            """, (
                span.span_id,
                span.trace_id,
                span.span_type,
                span.timestamp.isoformat(),
                json.dumps(span.data)
            ))

        conn.commit()
        conn.close()

    def get_traces(
        self,
        agent_name: Optional[str] = None,
        episode_range: Optional[tuple] = None,
        limit: Optional[int] = None
    ) -> List[Trace]:
        """
        Retrieve traces from store.

        Args:
            agent_name: Filter by agent name
            episode_range: (min_episode, max_episode) tuple
            limit: Maximum number of traces to return

        Returns:
            List of Trace objects
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        query = "SELECT trace_id, agent_name, episode_number, reward, metadata, created_at FROM traces WHERE 1=1"
        params = []

        if agent_name:
            query += " AND agent_name = ?"
            params.append(agent_name)

        if episode_range:
            query += " AND episode_number BETWEEN ? AND ?"
            params.extend(episode_range)

        query += " ORDER BY episode_number DESC"

        if limit:
            query += " LIMIT ?"
            params.append(limit)

        cursor.execute(query, params)
        rows = cursor.fetchall()

        traces = []
        for row in rows:
            trace_id, agent_name, episode_number, reward, metadata, created_at = row

            # Load spans
            cursor.execute("""
                SELECT span_id, span_type, timestamp, data
                FROM spans
                WHERE trace_id = ?
                ORDER BY timestamp
            """, (trace_id,))

            spans = []
            for span_row in cursor.fetchall():
                span_id, span_type, timestamp, data = span_row
                spans.append(Span(
                    span_id=span_id,
                    trace_id=trace_id,
                    span_type=span_type,
                    timestamp=datetime.fromisoformat(timestamp),
                    data=json.loads(data)
                ))

            traces.append(Trace(
                trace_id=trace_id,
                agent_name=agent_name,
                episode_number=episode_number,
                spans=spans,
                reward=reward,
                metadata=json.loads(metadata) if metadata else None,
                created_at=datetime.fromisoformat(created_at) if created_at else None
            ))

        conn.close()
        return traces

    def get_training_data(
        self,
        batch_size: int,
        agent_name: Optional[str] = None
    ) -> List[Trace]:
        """
        Get batch of traces for training.

        Args:
            batch_size: Number of traces to retrieve
            agent_name: Filter by agent name

        Returns:
            List of traces with rewards
        """
        traces = self.get_traces(agent_name=agent_name, limit=batch_size * 2)

        # Filter to only traces with rewards
        training_traces = [t for t in traces if t.reward is not None]

        return training_traces[:batch_size]

    def save_resource(
        self,
        resource_type: str,
        content: str,
        version: int,
        performance_metrics: Optional[Dict] = None
    ) -> str:
        """
        Save a learned resource (prompt template, strategy, etc.).

        Args:
            resource_type: Type of resource ("prompt_template", "strategy")
            content: Resource content
            version: Version number
            performance_metrics: Optional performance metrics

        Returns:
            Resource ID
        """
        resource_id = f"{resource_type}-v{version}"

        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute("""
            INSERT OR REPLACE INTO resources
            (resource_id, resource_type, version, content, performance_metrics)
            VALUES (?, ?, ?, ?, ?)
        """, (
            resource_id,
            resource_type,
            version,
            content,
            json.dumps(performance_metrics) if performance_metrics else None
        ))

        conn.commit()
        conn.close()

        logger.info(f"Saved resource {resource_id}")
        return resource_id

    def get_latest_resource(self, resource_type: str) -> Optional[Dict]:
        """
        Get latest version of a resource.

        Args:
            resource_type: Type of resource

        Returns:
            Resource dict or None
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute("""
            SELECT resource_id, version, content, performance_metrics, created_at
            FROM resources
            WHERE resource_type = ?
            ORDER BY version DESC
            LIMIT 1
        """, (resource_type,))

        row = cursor.fetchone()
        conn.close()

        if not row:
            return None

        resource_id, version, content, metrics, created_at = row
        return {
            'resource_id': resource_id,
            'resource_type': resource_type,
            'version': version,
            'content': content,
            'performance_metrics': json.loads(metrics) if metrics else None,
            'created_at': created_at
        }

    def get_statistics(self) -> Dict[str, Any]:
        """Get store statistics"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        stats = {}

        # Total traces
        cursor.execute("SELECT COUNT(*) FROM traces")
        stats['total_traces'] = cursor.fetchone()[0]

        # Traces by agent
        cursor.execute("""
            SELECT agent_name, COUNT(*)
            FROM traces
            GROUP BY agent_name
        """)
        stats['traces_by_agent'] = dict(cursor.fetchall())

        # Average reward
        cursor.execute("SELECT AVG(reward) FROM traces WHERE reward IS NOT NULL")
        stats['average_reward'] = cursor.fetchone()[0]

        # Recent performance (last 100 episodes)
        cursor.execute("""
            SELECT AVG(reward)
            FROM traces
            WHERE reward IS NOT NULL
            ORDER BY episode_number DESC
            LIMIT 100
        """)
        stats['recent_average_reward'] = cursor.fetchone()[0]

        conn.close()
        return stats


if __name__ == "__main__":
    # Test the store
    from src.utils.logging_config import setup_logging
    setup_logging()

    store = LightningStore()

    # Start a trace
    trace_id = store.start_trace("defender", episode_number=1)

    # Emit spans
    store.emit_span(trace_id, "prompt", {"prompt": "Analyze this code..."})
    store.emit_span(trace_id, "tool_call", {"tool": "llm", "args": {}})
    store.emit_span(trace_id, "observation", {"result": "Found vulnerability"})

    # Emit reward
    store.emit_reward(trace_id, reward=15.0)

    # End trace
    store.end_trace(trace_id)

    # Retrieve
    traces = store.get_traces(limit=10)
    print(f"Retrieved {len(traces)} traces")

    # Stats
    stats = store.get_statistics()
    print(f"Statistics: {json.dumps(stats, indent=2)}")
