"""
Tamper-Evident Audit Logging

Implements cryptographic signatures and hash chains for episode integrity.
Ensures audit trail cannot be tampered with undetected.
"""

import hashlib
import hmac
import json
import os
from typing import Optional, Dict, Any
from datetime import datetime
from pathlib import Path
import logging

logger = logging.getLogger(__name__)


class TamperEvidentLogger:
    """
    Cryptographically signed audit log with hash chain.

    Features:
    - SHA-256 hashing of episode data
    - HMAC-SHA256 signing with secret key
    - Hash chain linking episodes (each references previous hash)
    - Append-only audit log
    - Tamper detection via chain verification
    """

    def __init__(
        self,
        audit_log_path: str = "data/audit/audit.log",
        secret_key: Optional[str] = None
    ):
        """
        Initialize tamper-evident logger.

        Args:
            audit_log_path: Path to append-only audit log file
            secret_key: Secret key for HMAC signing (from env or generated)
        """
        self.audit_log_path = Path(audit_log_path)
        self.audit_log_path.parent.mkdir(parents=True, exist_ok=True)

        # Get or generate secret key
        if secret_key is None:
            secret_key = os.getenv("ASDS_AUDIT_SECRET_KEY")
            if secret_key is None:
                # Generate a random secret key if not provided
                secret_key = os.urandom(32).hex()
                logger.warning(
                    "No ASDS_AUDIT_SECRET_KEY found. Generated random key. "
                    "Set ASDS_AUDIT_SECRET_KEY environment variable for production."
                )

        self.secret_key = secret_key.encode() if isinstance(secret_key, str) else secret_key

        # Track previous hash for chain
        self.previous_hash: Optional[str] = None

        # Load previous hash from audit log if exists
        self._load_previous_hash()

    def _load_previous_hash(self):
        """Load the last hash from audit log to continue chain"""
        if not self.audit_log_path.exists():
            return

        try:
            with open(self.audit_log_path, 'r') as f:
                lines = f.readlines()
                if lines:
                    # Get last entry's signature
                    last_entry = json.loads(lines[-1])
                    self.previous_hash = last_entry.get('signature')
        except Exception as e:
            logger.warning(f"Could not load previous hash from audit log: {e}")

    def compute_hash(self, data: Dict[str, Any]) -> str:
        """
        Compute SHA-256 hash of data.

        Args:
            data: Dictionary to hash

        Returns:
            Hexadecimal hash string
        """
        # Convert to sorted JSON string for deterministic hashing
        data_str = json.dumps(data, sort_keys=True, default=str)
        return hashlib.sha256(data_str.encode()).hexdigest()

    def sign_episode(self, episode_data: Dict[str, Any]) -> Dict[str, str]:
        """
        Sign episode data with HMAC and create hash chain entry.

        Args:
            episode_data: Episode data to sign

        Returns:
            Dictionary containing:
                - data_hash: SHA-256 hash of episode data
                - signature: HMAC-SHA256 signature
                - previous_hash: Hash of previous episode (for chain)
                - timestamp: ISO format timestamp
        """
        # Compute data hash
        data_hash = self.compute_hash(episode_data)

        # Create chain data: include previous hash
        chain_data = {
            "data_hash": data_hash,
            "previous_hash": self.previous_hash,
            "timestamp": datetime.now().isoformat()
        }

        # Compute HMAC signature over chain data
        chain_str = json.dumps(chain_data, sort_keys=True)
        signature = hmac.new(
            self.secret_key,
            chain_str.encode(),
            hashlib.sha256
        ).hexdigest()

        # Update previous hash for next episode
        self.previous_hash = signature

        return {
            "data_hash": data_hash,
            "signature": signature,
            "previous_hash": chain_data["previous_hash"],
            "timestamp": chain_data["timestamp"]
        }

    def log_episode(
        self,
        episode_number: int,
        episode_data: Dict[str, Any],
        metadata: Optional[Dict[str, Any]] = None
    ) -> Dict[str, str]:
        """
        Create tamper-evident audit log entry for episode.

        Args:
            episode_number: Episode number
            episode_data: Episode data to log and sign
            metadata: Optional additional metadata

        Returns:
            Audit entry with signature
        """
        # Sign the episode
        signature_data = self.sign_episode(episode_data)

        # Create audit entry
        audit_entry = {
            "episode_number": episode_number,
            "data_hash": signature_data["data_hash"],
            "signature": signature_data["signature"],
            "previous_hash": signature_data["previous_hash"],
            "timestamp": signature_data["timestamp"],
            "metadata": metadata or {}
        }

        # Append to audit log (append-only)
        self._append_to_audit_log(audit_entry)

        return audit_entry

    def _append_to_audit_log(self, entry: Dict[str, Any]):
        """
        Append entry to audit log file (append-only).

        Args:
            entry: Audit entry to append
        """
        try:
            # Open in append mode only (write-once semantics)
            with open(self.audit_log_path, 'a') as f:
                f.write(json.dumps(entry) + '\n')
        except Exception as e:
            logger.error(f"Failed to write to audit log: {e}")
            raise

    def verify_chain(self) -> bool:
        """
        Verify integrity of entire audit log chain.

        Returns:
            True if chain is valid, False if tampered

        Raises:
            ValueError: If chain is broken or signatures invalid
        """
        if not self.audit_log_path.exists():
            return True  # Empty log is valid

        entries = []
        with open(self.audit_log_path, 'r') as f:
            for line in f:
                entries.append(json.loads(line))

        if not entries:
            return True

        # Verify each entry in chain
        previous_hash = None
        for i, entry in enumerate(entries):
            # Check previous hash matches
            if entry.get('previous_hash') != previous_hash:
                raise ValueError(
                    f"Chain broken at entry {i}: "
                    f"expected previous_hash={previous_hash}, "
                    f"got {entry.get('previous_hash')}"
                )

            # Verify HMAC signature
            chain_data = {
                "data_hash": entry['data_hash'],
                "previous_hash": entry['previous_hash'],
                "timestamp": entry['timestamp']
            }
            chain_str = json.dumps(chain_data, sort_keys=True)
            expected_signature = hmac.new(
                self.secret_key,
                chain_str.encode(),
                hashlib.sha256
            ).hexdigest()

            if entry['signature'] != expected_signature:
                raise ValueError(
                    f"Invalid signature at entry {i}: "
                    f"signature mismatch (possible tampering)"
                )

            # Update for next iteration
            previous_hash = entry['signature']

        logger.info(f"Audit chain verified: {len(entries)} entries, integrity intact")
        return True

    def get_audit_stats(self) -> Dict[str, Any]:
        """
        Get statistics about audit log.

        Returns:
            Dictionary with audit log stats
        """
        if not self.audit_log_path.exists():
            return {
                "total_entries": 0,
                "first_timestamp": None,
                "last_timestamp": None,
                "chain_valid": True
            }

        entries = []
        with open(self.audit_log_path, 'r') as f:
            for line in f:
                entries.append(json.loads(line))

        try:
            chain_valid = self.verify_chain()
        except ValueError as e:
            chain_valid = False
            logger.error(f"Chain verification failed: {e}")

        return {
            "total_entries": len(entries),
            "first_timestamp": entries[0]['timestamp'] if entries else None,
            "last_timestamp": entries[-1]['timestamp'] if entries else None,
            "chain_valid": chain_valid,
            "audit_log_path": str(self.audit_log_path)
        }


if __name__ == "__main__":
    # Test tamper-evident logger
    import tempfile

    # Create test logger
    test_log = tempfile.mktemp(suffix='.log')
    logger = TamperEvidentLogger(audit_log_path=test_log, secret_key="test_secret")

    # Log some test episodes
    for i in range(5):
        episode_data = {
            "episode": i,
            "reward": i * 10,
            "findings": ["test1", "test2"]
        }
        entry = logger.log_episode(i, episode_data)
        print(f"Episode {i} signed: {entry['signature'][:16]}...")

    # Verify chain
    print("\nVerifying chain...")
    try:
        logger.verify_chain()
        print("✓ Chain verified successfully!")
    except ValueError as e:
        print(f"✗ Chain verification failed: {e}")

    # Get stats
    stats = logger.get_audit_stats()
    print(f"\nAudit log stats:")
    print(f"  Total entries: {stats['total_entries']}")
    print(f"  Chain valid: {stats['chain_valid']}")
    print(f"  First: {stats['first_timestamp']}")
    print(f"  Last: {stats['last_timestamp']}")

    # Clean up
    os.remove(test_log)
    print("\nTest completed!")
