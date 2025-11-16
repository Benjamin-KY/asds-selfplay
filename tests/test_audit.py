"""
Tests for tamper-evident audit logging system.
"""

import pytest
import tempfile
import json
import os
from pathlib import Path

from src.utils.audit import TamperEvidentLogger


class TestTamperEvidentLogger:
    """Test tamper-evident audit logging"""

    def test_initialization(self, temp_dir):
        """Test logger initialization"""
        audit_log = temp_dir / "audit.log"
        logger = TamperEvidentLogger(
            audit_log_path=str(audit_log),
            secret_key="test_secret_key"
        )

        assert logger.audit_log_path == audit_log
        assert logger.previous_hash is None
        assert audit_log.parent.exists()

    def test_compute_hash(self, temp_dir):
        """Test SHA-256 hash computation"""
        logger = TamperEvidentLogger(
            audit_log_path=str(temp_dir / "audit.log"),
            secret_key="test_secret"
        )

        data = {"episode": 1, "reward": 10.0}
        hash1 = logger.compute_hash(data)

        # Hash should be deterministic
        hash2 = logger.compute_hash(data)
        assert hash1 == hash2

        # Hash should be 64 chars (SHA-256 hex)
        assert len(hash1) == 64

        # Different data should produce different hash
        data2 = {"episode": 2, "reward": 20.0}
        hash3 = logger.compute_hash(data2)
        assert hash1 != hash3

    def test_sign_episode(self, temp_dir):
        """Test episode signing with HMAC"""
        logger = TamperEvidentLogger(
            audit_log_path=str(temp_dir / "audit.log"),
            secret_key="test_secret"
        )

        episode_data = {
            "episode_number": 1,
            "reward": 15.0,
            "findings": ["sql_injection"]
        }

        signature_data = logger.sign_episode(episode_data)

        assert "data_hash" in signature_data
        assert "signature" in signature_data
        assert "previous_hash" in signature_data
        assert "timestamp" in signature_data

        # Signature should be 64 chars (HMAC-SHA256 hex)
        assert len(signature_data["signature"]) == 64

        # Previous hash should be None for first episode
        assert signature_data["previous_hash"] is None

        # Logger should update previous_hash
        assert logger.previous_hash == signature_data["signature"]

    def test_log_episode(self, temp_dir):
        """Test logging an episode to audit file"""
        audit_log = temp_dir / "audit.log"
        logger = TamperEvidentLogger(
            audit_log_path=str(audit_log),
            secret_key="test_secret"
        )

        episode_data = {
            "code": "query = f'SELECT * FROM users WHERE id={id}'",
            "findings": ["sql_injection"],
            "reward": 15.0
        }

        audit_entry = logger.log_episode(
            episode_number=1,
            episode_data=episode_data,
            metadata={"language": "python"}
        )

        # Check return value
        assert audit_entry["episode_number"] == 1
        assert "signature" in audit_entry
        assert "data_hash" in audit_entry

        # Check file was created
        assert audit_log.exists()

        # Check file contents
        with open(audit_log) as f:
            lines = f.readlines()
            assert len(lines) == 1
            entry = json.loads(lines[0])
            assert entry["episode_number"] == 1
            assert entry["signature"] == audit_entry["signature"]

    def test_hash_chain(self, temp_dir):
        """Test hash chain links episodes correctly"""
        logger = TamperEvidentLogger(
            audit_log_path=str(temp_dir / "audit.log"),
            secret_key="test_secret"
        )

        # Log multiple episodes
        signatures = []
        for i in range(5):
            episode_data = {"episode": i, "reward": i * 10}
            entry = logger.log_episode(i, episode_data)
            signatures.append(entry["signature"])

        # Verify chain structure
        with open(temp_dir / "audit.log") as f:
            lines = f.readlines()
            assert len(lines) == 5

            for i, line in enumerate(lines):
                entry = json.loads(line)
                if i == 0:
                    # First episode has no previous hash
                    assert entry["previous_hash"] is None
                else:
                    # Each episode links to previous signature
                    assert entry["previous_hash"] == signatures[i - 1]

    def test_verify_chain_valid(self, temp_dir):
        """Test verifying valid audit chain"""
        logger = TamperEvidentLogger(
            audit_log_path=str(temp_dir / "audit.log"),
            secret_key="test_secret"
        )

        # Create valid chain
        for i in range(10):
            logger.log_episode(i, {"episode": i, "reward": i * 5})

        # Verification should pass
        assert logger.verify_chain() is True

    def test_verify_chain_tampered(self, temp_dir):
        """Test detecting tampered audit chain"""
        audit_log = temp_dir / "audit.log"
        logger = TamperEvidentLogger(
            audit_log_path=str(audit_log),
            secret_key="test_secret"
        )

        # Create valid chain
        for i in range(5):
            logger.log_episode(i, {"episode": i, "reward": i * 10})

        # Tamper with middle entry's data_hash (which is part of signature verification)
        with open(audit_log, 'r') as f:
            lines = f.readlines()

        # Modify episode 2's data_hash to simulate tampering
        entry = json.loads(lines[2])
        entry["data_hash"] = "0" * 64  # Replace with fake hash
        lines[2] = json.dumps(entry) + '\n'

        with open(audit_log, 'w') as f:
            f.writelines(lines)

        # Verification should fail because signature won't match tampered data_hash
        with pytest.raises(ValueError, match="Invalid signature"):
            logger.verify_chain()

    def test_verify_chain_broken_link(self, temp_dir):
        """Test detecting broken chain link"""
        audit_log = temp_dir / "audit.log"
        logger = TamperEvidentLogger(
            audit_log_path=str(audit_log),
            secret_key="test_secret"
        )

        # Create valid chain
        for i in range(5):
            logger.log_episode(i, {"episode": i, "reward": i * 10})

        # Break chain by modifying previous_hash
        with open(audit_log, 'r') as f:
            lines = f.readlines()

        entry = json.loads(lines[2])
        entry["previous_hash"] = "invalid_hash"
        lines[2] = json.dumps(entry) + '\n'

        with open(audit_log, 'w') as f:
            f.writelines(lines)

        # Verification should fail
        with pytest.raises(ValueError, match="Chain broken"):
            logger.verify_chain()

    def test_verify_empty_chain(self, temp_dir):
        """Test verifying empty audit log"""
        logger = TamperEvidentLogger(
            audit_log_path=str(temp_dir / "audit.log"),
            secret_key="test_secret"
        )

        # Empty chain should be valid
        assert logger.verify_chain() is True

    def test_continue_chain_after_restart(self, temp_dir):
        """Test continuing chain after logger restart"""
        audit_log = temp_dir / "audit.log"
        secret_key = "test_secret"

        # First logger session
        logger1 = TamperEvidentLogger(
            audit_log_path=str(audit_log),
            secret_key=secret_key
        )
        logger1.log_episode(0, {"episode": 0})
        logger1.log_episode(1, {"episode": 1})
        last_sig = logger1.previous_hash

        # Second logger session (restart)
        logger2 = TamperEvidentLogger(
            audit_log_path=str(audit_log),
            secret_key=secret_key
        )

        # Should load previous hash
        assert logger2.previous_hash == last_sig

        # Continue chain
        logger2.log_episode(2, {"episode": 2})

        # Verify full chain
        assert logger2.verify_chain() is True

    def test_get_audit_stats(self, temp_dir):
        """Test getting audit statistics"""
        logger = TamperEvidentLogger(
            audit_log_path=str(temp_dir / "audit.log"),
            secret_key="test_secret"
        )

        # Empty stats
        stats = logger.get_audit_stats()
        assert stats["total_entries"] == 0
        assert stats["chain_valid"] is True

        # Add episodes
        for i in range(10):
            logger.log_episode(i, {"episode": i})

        # Check stats
        stats = logger.get_audit_stats()
        assert stats["total_entries"] == 10
        assert stats["chain_valid"] is True
        assert stats["first_timestamp"] is not None
        assert stats["last_timestamp"] is not None

    def test_secret_key_affects_signature(self, temp_dir):
        """Test different secret keys produce different signatures"""
        episode_data = {"episode": 1, "reward": 10.0}

        logger1 = TamperEvidentLogger(
            audit_log_path=str(temp_dir / "audit1.log"),
            secret_key="secret1"
        )
        entry1 = logger1.log_episode(1, episode_data)

        logger2 = TamperEvidentLogger(
            audit_log_path=str(temp_dir / "audit2.log"),
            secret_key="secret2"
        )
        entry2 = logger2.log_episode(1, episode_data)

        # Same data, different secrets = different signatures
        assert entry1["signature"] != entry2["signature"]

    def test_append_only_semantics(self, temp_dir):
        """Test audit log is append-only"""
        audit_log = temp_dir / "audit.log"
        logger = TamperEvidentLogger(
            audit_log_path=str(audit_log),
            secret_key="test_secret"
        )

        # Log 3 episodes
        for i in range(3):
            logger.log_episode(i, {"episode": i})

        # Check file was opened in append mode (can't test directly,
        # but verify entries accumulate correctly)
        with open(audit_log) as f:
            lines = f.readlines()
            assert len(lines) == 3

        # Log more episodes
        for i in range(3, 6):
            logger.log_episode(i, {"episode": i})

        # Should have all 6 entries
        with open(audit_log) as f:
            lines = f.readlines()
            assert len(lines) == 6

    def test_large_episode_data(self, temp_dir):
        """Test handling large episode data"""
        logger = TamperEvidentLogger(
            audit_log_path=str(temp_dir / "audit.log"),
            secret_key="test_secret"
        )

        # Create large episode data
        episode_data = {
            "code": "x" * 10000,  # 10KB of code
            "findings": [f"finding_{i}" for i in range(100)],
            "reward": 50.0
        }

        entry = logger.log_episode(1, episode_data)

        assert "signature" in entry
        assert logger.verify_chain() is True

    def test_special_characters_in_data(self, temp_dir):
        """Test handling special characters in episode data"""
        logger = TamperEvidentLogger(
            audit_log_path=str(temp_dir / "audit.log"),
            secret_key="test_secret"
        )

        episode_data = {
            "code": "SELECT * FROM users WHERE name='O\\'Brien'",
            "unicode": "Hello 世界 🔐",
            "newlines": "line1\nline2\nline3"
        }

        entry = logger.log_episode(1, episode_data)

        assert "signature" in entry
        assert logger.verify_chain() is True

    def test_metadata_in_audit_entry(self, temp_dir):
        """Test metadata is stored in audit entries"""
        logger = TamperEvidentLogger(
            audit_log_path=str(temp_dir / "audit.log"),
            secret_key="test_secret"
        )

        episode_data = {"episode": 1}
        metadata = {
            "language": "python",
            "true_positives": 5,
            "false_positives": 2
        }

        entry = logger.log_episode(1, episode_data, metadata)

        assert entry["metadata"] == metadata

        # Verify metadata stored in file
        with open(temp_dir / "audit.log") as f:
            stored_entry = json.loads(f.read())
            assert stored_entry["metadata"] == metadata


class TestAuditIntegration:
    """Integration tests with other components"""

    def test_integration_with_self_play(self, temp_dir, mock_llm):
        """Test audit logging integration with self-play training"""
        from src.knowledge.graph import SecurityKnowledgeGraph
        from src.agents.defender import DefenderAgent
        from src.agents.attacker import AttackerAgent
        from src.core.self_play import SelfPlayTrainer

        # Create components
        kg = SecurityKnowledgeGraph(db_path=str(temp_dir / "kg.db"))
        defender = DefenderAgent(kg, llm_client=mock_llm)
        attacker = AttackerAgent(llm_client=mock_llm)

        # Create trainer (which initializes audit logger)
        trainer = SelfPlayTrainer(
            kg, defender, attacker,
            episodes_dir=str(temp_dir / "episodes")
        )

        # Verify audit logger initialized
        assert trainer.audit_logger is not None
        assert isinstance(trainer.audit_logger, TamperEvidentLogger)

    def test_audit_entry_created_on_episode_save(self, temp_dir, mock_llm):
        """Test audit entry is created when episode is saved"""
        from src.knowledge.graph import SecurityKnowledgeGraph
        from src.agents.defender import DefenderAgent, Finding
        from src.agents.attacker import AttackerAgent, Exploit
        from src.core.self_play import SelfPlayTrainer, TrainingEpisode
        from datetime import datetime

        # Setup with isolated audit log
        audit_log_path = str(temp_dir / "test_audit.log")
        kg = SecurityKnowledgeGraph(db_path=str(temp_dir / "kg.db"))
        defender = DefenderAgent(kg, llm_client=mock_llm)
        attacker = AttackerAgent(llm_client=mock_llm)
        trainer = SelfPlayTrainer(
            kg, defender, attacker,
            episodes_dir=str(temp_dir / "episodes")
        )

        # Replace with isolated audit logger
        trainer.audit_logger = TamperEvidentLogger(
            audit_log_path=audit_log_path,
            secret_key="test_secret"
        )

        # Create test episode
        episode = TrainingEpisode(
            episode_number=1,
            code_sample="test code",
            language="python",
            defender_findings=[],
            defense_time=1.0,
            original_exploits=[],
            fixed_exploits=[],
            attack_time=1.0,
            reward=10.0,
            attacker_reward=5.0,
            true_positives=1,
            false_positives=0,
            false_negatives=0,
            fixes_that_worked=1,
            fixes_broken=0,
            novel_exploit_types=0,
            timestamp=datetime.now()
        )

        # Save episode
        trainer._save_episode(episode)

        # Verify audit entry created
        stats = trainer.audit_logger.get_audit_stats()
        assert stats["total_entries"] == 1

        # Verify chain is valid
        assert trainer.audit_logger.verify_chain() is True


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
