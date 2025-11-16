"""
Tests for LightningStore and RL infrastructure.
"""

import pytest
from datetime import datetime

from src.rl.store import LightningStore, Trace, Span


class TestSpan:
    """Test Span dataclass"""

    def test_span_creation(self):
        """Test span can be created"""
        span = Span(
            span_id="test-span-1",
            trace_id="test-trace-1",
            span_type="prompt",
            timestamp=datetime.now(),
            data={"test": "data"}
        )

        assert span.span_id == "test-span-1"
        assert span.span_type == "prompt"
        assert "test" in span.data

    def test_span_to_dict(self):
        """Test span serialization"""
        span = Span(
            span_id="test-span-1",
            trace_id="test-trace-1",
            span_type="prompt",
            timestamp=datetime.now(),
            data={"test": "data"}
        )

        span_dict = span.to_dict()
        assert "span_id" in span_dict
        assert "timestamp" in span_dict
        assert isinstance(span_dict["timestamp"], str)  # ISO format


class TestTrace:
    """Test Trace dataclass"""

    def test_trace_creation(self):
        """Test trace can be created"""
        trace = Trace(
            trace_id="test-trace-1",
            agent_name="defender",
            episode_number=1,
            spans=[],
            reward=10.0
        )

        assert trace.trace_id == "test-trace-1"
        assert trace.agent_name == "defender"
        assert trace.reward == 10.0

    def test_trace_with_spans(self):
        """Test trace with spans"""
        spans = [
            Span(
                span_id="span-1",
                trace_id="test-trace-1",
                span_type="prompt",
                timestamp=datetime.now(),
                data={}
            )
        ]

        trace = Trace(
            trace_id="test-trace-1",
            agent_name="defender",
            episode_number=1,
            spans=spans
        )

        assert len(trace.spans) == 1


class TestLightningStore:
    """Test LightningStore"""

    def test_initialization(self, test_rl_store):
        """Test store initializes"""
        assert test_rl_store is not None
        assert test_rl_store.db_path is not None

    def test_start_trace(self, test_rl_store):
        """Test starting a trace"""
        trace_id = test_rl_store.start_trace(
            agent_name="defender",
            episode_number=1
        )

        assert trace_id is not None
        assert trace_id in test_rl_store._active_traces

    def test_emit_span(self, test_rl_store):
        """Test emitting a span"""
        trace_id = test_rl_store.start_trace(
            agent_name="defender",
            episode_number=1
        )

        span_id = test_rl_store.emit_span(
            trace_id=trace_id,
            span_type="prompt",
            data={"prompt": "test"}
        )

        assert span_id is not None
        assert len(test_rl_store._span_buffer[trace_id]) == 1

    def test_emit_reward(self, test_rl_store):
        """Test emitting a reward"""
        trace_id = test_rl_store.start_trace(
            agent_name="defender",
            episode_number=1
        )

        test_rl_store.emit_reward(
            trace_id=trace_id,
            reward=15.0
        )

        trace = test_rl_store._active_traces[trace_id]
        assert trace.reward == 15.0

    def test_end_trace(self, test_rl_store):
        """Test ending and persisting a trace"""
        trace_id = test_rl_store.start_trace(
            agent_name="defender",
            episode_number=1
        )

        test_rl_store.emit_span(
            trace_id=trace_id,
            span_type="prompt",
            data={"prompt": "test"}
        )

        test_rl_store.emit_reward(trace_id, reward=10.0)

        test_rl_store.end_trace(trace_id)

        # Should be removed from active traces
        assert trace_id not in test_rl_store._active_traces

        # Should be retrievable from database
        traces = test_rl_store.get_traces(limit=1)
        assert len(traces) == 1
        assert traces[0].trace_id == trace_id

    def test_get_traces_filter_by_agent(self, test_rl_store):
        """Test filtering traces by agent name"""
        # Create defender trace
        trace_id_1 = test_rl_store.start_trace("defender", 1)
        test_rl_store.emit_reward(trace_id_1, 10.0)
        test_rl_store.end_trace(trace_id_1)

        # Create attacker trace
        trace_id_2 = test_rl_store.start_trace("attacker", 1)
        test_rl_store.emit_reward(trace_id_2, 5.0)
        test_rl_store.end_trace(trace_id_2)

        # Filter by defender
        defender_traces = test_rl_store.get_traces(agent_name="defender")
        assert len(defender_traces) == 1
        assert defender_traces[0].agent_name == "defender"

    def test_get_traces_episode_range(self, test_rl_store):
        """Test filtering traces by episode range"""
        for episode in [1, 5, 10, 15]:
            trace_id = test_rl_store.start_trace("defender", episode)
            test_rl_store.emit_reward(trace_id, float(episode))
            test_rl_store.end_trace(trace_id)

        # Get episodes 5-10
        traces = test_rl_store.get_traces(episode_range=(5, 10))

        episode_numbers = {t.episode_number for t in traces}
        assert 5 in episode_numbers
        assert 10 in episode_numbers
        assert 1 not in episode_numbers
        assert 15 not in episode_numbers

    def test_get_training_data(self, test_rl_store):
        """Test getting training data"""
        # Create traces with rewards
        for i in range(10):
            trace_id = test_rl_store.start_trace("defender", i)
            test_rl_store.emit_reward(trace_id, float(i * 2))
            test_rl_store.end_trace(trace_id)

        # Get batch
        training_data = test_rl_store.get_training_data(batch_size=5)

        assert len(training_data) <= 5
        assert all(t.reward is not None for t in training_data)

    def test_save_and_get_resource(self, test_rl_store):
        """Test saving and retrieving resources"""
        resource_id = test_rl_store.save_resource(
            resource_type="prompt_template",
            content="Test prompt template",
            version=1,
            performance_metrics={"accuracy": 0.85}
        )

        assert resource_id is not None

        # Retrieve latest
        resource = test_rl_store.get_latest_resource("prompt_template")

        assert resource is not None
        assert resource["version"] == 1
        assert resource["content"] == "Test prompt template"
        assert resource["performance_metrics"]["accuracy"] == 0.85

    def test_resource_versioning(self, test_rl_store):
        """Test resource version management"""
        # Save multiple versions
        test_rl_store.save_resource(
            "prompt_template", "v1", 1
        )
        test_rl_store.save_resource(
            "prompt_template", "v2", 2
        )
        test_rl_store.save_resource(
            "prompt_template", "v3", 3
        )

        # Should get latest version
        resource = test_rl_store.get_latest_resource("prompt_template")
        assert resource["version"] == 3
        assert resource["content"] == "v3"

    def test_get_statistics(self, test_rl_store):
        """Test getting store statistics"""
        # Create some traces
        for i in range(5):
            trace_id = test_rl_store.start_trace("defender", i)
            test_rl_store.emit_reward(trace_id, float(i * 10))
            test_rl_store.end_trace(trace_id)

        stats = test_rl_store.get_statistics()

        assert stats["total_traces"] == 5
        assert "average_reward" in stats
        assert "traces_by_agent" in stats

    def test_trace_with_multiple_spans(self, test_rl_store):
        """Test trace with multiple span types"""
        trace_id = test_rl_store.start_trace("defender", 1)

        # Emit different span types
        test_rl_store.emit_span(trace_id, "prompt", {"prompt": "test"})
        test_rl_store.emit_span(trace_id, "tool_call", {"tool": "llm"})
        test_rl_store.emit_span(trace_id, "observation", {"result": "found"})
        test_rl_store.emit_reward(trace_id, 15.0)

        test_rl_store.end_trace(trace_id)

        # Retrieve and check spans
        traces = test_rl_store.get_traces(limit=1)
        trace = traces[0]

        assert len(trace.spans) >= 3  # At least our 3 spans (reward creates another)

        span_types = {s.span_type for s in trace.spans}
        assert "prompt" in span_types
        assert "tool_call" in span_types
        assert "observation" in span_types


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
