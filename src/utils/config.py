"""
Configuration management for ASDS Self-Play.

Loads settings from config.yaml and provides type-safe access.
"""

import yaml
from pathlib import Path
from typing import Any, Dict, Optional
from dataclasses import dataclass


@dataclass
class ModelConfig:
    """Model configuration"""
    name: str
    temperature: Dict[str, float]
    max_tokens: Dict[str, int]


@dataclass
class RewardsConfig:
    """Reward function weights"""
    true_positive: float
    false_positive: float
    false_negative: float
    fix_worked: float
    fix_failed: float


@dataclass
class PatternsConfig:
    """Pattern effectiveness thresholds"""
    min_effectiveness: float
    max_ineffective: float
    min_observations: int
    prune_threshold: float
    prune_min_observations: int
    recent_patterns_limit: int
    effective_patterns_limit: int


@dataclass
class AgentLightningConfig:
    """Agent Lightning RL settings"""
    enabled: bool
    algorithm: str
    learning_rate: float
    batch_size: int
    update_frequency: int
    episodes_per_batch: int
    exploration_rate: float
    save_frequency: int


@dataclass
class TrainingConfig:
    """Training configuration"""
    episodes_dir: str
    checkpoints_dir: str
    logs_dir: str
    save_traces: bool
    verbose: bool


@dataclass
class LoggingConfig:
    """Logging configuration"""
    level: str
    format: str
    file: str
    console: bool


class Config:
    """
    Central configuration object.

    Usage:
        config = Config.load()
        model_name = config.model.name
        reward = config.rewards.true_positive
    """

    def __init__(self, config_dict: Dict[str, Any]):
        self.raw = config_dict

        # Parse sections
        self.model = ModelConfig(**config_dict['model'])
        self.rewards = RewardsConfig(**config_dict['rewards'])
        self.patterns = PatternsConfig(**config_dict['patterns'])
        self.agent_lightning = AgentLightningConfig(**config_dict['agent_lightning'])
        self.training = TrainingConfig(**config_dict['training'])
        self.logging = LoggingConfig(**config_dict['logging'])

        # Direct access to other sections
        self.prompts = config_dict.get('prompts', {})
        self.database = config_dict.get('database', {})
        self.performance = config_dict.get('performance', {})

    @classmethod
    def load(cls, config_path: Optional[str] = None) -> 'Config':
        """
        Load configuration from YAML file.

        Args:
            config_path: Path to config file. Defaults to config.yaml in project root.

        Returns:
            Config object
        """
        if config_path is None:
            # Default to project root config.yaml
            project_root = Path(__file__).parent.parent.parent
            config_path = project_root / "config.yaml"

        config_path = Path(config_path)

        if not config_path.exists():
            raise FileNotFoundError(f"Config file not found: {config_path}")

        with open(config_path, 'r') as f:
            config_dict = yaml.safe_load(f)

        return cls(config_dict)

    def get(self, key: str, default: Any = None) -> Any:
        """
        Get configuration value by dot notation.

        Example:
            config.get('model.name')
            config.get('rewards.true_positive')
        """
        keys = key.split('.')
        value = self.raw

        for k in keys:
            if isinstance(value, dict):
                value = value.get(k)
                if value is None:
                    return default
            else:
                return default

        return value


# Global config instance
_config: Optional[Config] = None


def get_config() -> Config:
    """
    Get global configuration instance (singleton pattern).

    Returns:
        Config object
    """
    global _config
    if _config is None:
        _config = Config.load()
    return _config


def reload_config(config_path: Optional[str] = None):
    """
    Reload configuration from file.

    Args:
        config_path: Path to config file
    """
    global _config
    _config = Config.load(config_path)


if __name__ == "__main__":
    # Test config loading
    config = Config.load()

    print("Configuration loaded successfully!")
    print(f"Model: {config.model.name}")
    print(f"Analysis temperature: {config.model.temperature['analysis']}")
    print(f"True positive reward: {config.rewards.true_positive}")
    print(f"Agent Lightning enabled: {config.agent_lightning.enabled}")
    print(f"RL algorithm: {config.agent_lightning.algorithm}")
