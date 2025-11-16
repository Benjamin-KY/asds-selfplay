"""
Pytest configuration and shared fixtures.
"""

import pytest
import tempfile
import shutil
from pathlib import Path
from unittest.mock import Mock

from src.knowledge.graph import SecurityKnowledgeGraph, SecurityPattern, PatternType
from src.rl.store import LightningStore


@pytest.fixture
def temp_dir():
    """Create temporary directory for tests"""
    temp_path = Path(tempfile.mkdtemp())
    yield temp_path
    shutil.rmtree(temp_path)


@pytest.fixture
def test_knowledge_graph(temp_dir):
    """Create temporary knowledge graph for testing"""
    db_path = temp_dir / "test_knowledge.db"
    kg = SecurityKnowledgeGraph(db_path=str(db_path))
    return kg


@pytest.fixture
def test_rl_store(temp_dir):
    """Create temporary RL store for testing"""
    db_path = temp_dir / "test_rl_store.db"
    store = LightningStore(db_path=str(db_path))
    return store


@pytest.fixture
def sample_vulnerable_code():
    """Sample vulnerable code for testing"""
    return '''
def login(username, password):
    query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
    result = db.execute(query)
    return result
'''


@pytest.fixture
def sample_pattern():
    """Sample security pattern"""
    return SecurityPattern(
        id="TEST-PATTERN-001",
        name="Test SQL Injection Pattern",
        pattern_type=PatternType.SQL_INJECTION,
        code_example='query = f"SELECT * FROM users WHERE id={user_id}"',
        language="python",
        risk_level="critical",
        cwe_id="CWE-89"
    )


@pytest.fixture
def mock_llm():
    """Mock LLM client for testing without API key"""
    return Mock()
