"""
Self-Play Training Loop

Orchestrates defender vs attacker episodes for learning.
"""

import json
from typing import List, Dict, Optional, Any
from dataclasses import dataclass, asdict
from datetime import datetime
from pathlib import Path

from src.agents.defender import DefenderAgent, Finding
from src.agents.attacker import AttackerAgent, Exploit
from src.knowledge.graph import SecurityKnowledgeGraph
from src.utils.config import get_config
from src.utils.logging_config import get_logger

logger = get_logger(__name__)


@dataclass
class TrainingEpisode:
    """Results from one training episode"""
    episode_number: int
    code_sample: str
    language: str

    # Defense results
    defender_findings: List[Finding]
    defense_time: float

    # Attack results
    original_exploits: List[Exploit]
    fixed_exploits: List[Exploit]
    attack_time: float

    # Learning metrics
    reward: float
    attacker_reward: float
    true_positives: int
    false_positives: int
    false_negatives: int
    fixes_that_worked: int
    fixes_broken: int
    novel_exploit_types: int

    timestamp: datetime

    def to_dict(self) -> dict:
        return {
            **asdict(self),
            "defender_findings": [f.to_dict() for f in self.defender_findings],
            "original_exploits": [e.to_dict() for e in self.original_exploits],
            "fixed_exploits": [e.to_dict() for e in self.fixed_exploits],
            "timestamp": self.timestamp.isoformat()
        }


class SelfPlayTrainer:
    """
    Orchestrates self-play training between defender and attacker.

    This is where the learning happens!
    """

    def __init__(
        self,
        knowledge_graph: SecurityKnowledgeGraph,
        defender: DefenderAgent,
        attacker: AttackerAgent,
        episodes_dir: Optional[str] = None,
        rl_store: Optional[Any] = None,
        rl_trainer: Optional[Any] = None
    ):
        self.kg = knowledge_graph
        self.defender = defender
        self.attacker = attacker

        # Load config
        config = get_config()
        self.episodes_dir = Path(episodes_dir or config.training.episodes_dir)
        self.episodes_dir.mkdir(parents=True, exist_ok=True)

        # RL integration
        self.rl_store = rl_store
        self.rl_trainer = rl_trainer
        self.rl_enabled = config.agent_lightning.enabled and rl_store is not None

        # Reward function weights from config
        self.reward_weights = {
            'true_positive': config.rewards.true_positive,
            'false_positive': config.rewards.false_positive,
            'false_negative': config.rewards.false_negative,
            'fix_worked': config.rewards.fix_worked
        }

        # Attacker reward function weights from config
        self.attacker_reward_weights = {
            'false_negatives': config.attacker_rewards.false_negatives,
            'true_positives': config.attacker_rewards.true_positives,
            'fixes_broken': config.attacker_rewards.fixes_broken,
            'novel_exploits': config.attacker_rewards.novel_exploits
        }

        self.episode_count = 0
        self.episodes: List[TrainingEpisode] = []

        # Track historical exploit types for novelty detection
        self.seen_exploit_types: set = set()

        logger.info(f"SelfPlayTrainer initialized (RL enabled: {self.rl_enabled})")

    def train_episode(
        self,
        code_sample: str,
        language: str = "python"
    ) -> TrainingEpisode:
        """
        Run one training episode.

        Flow:
        1. Defender analyzes code
        2. Attacker exploits original code
        3. Defender suggests fixes
        4. Attacker exploits fixed code
        5. Calculate reward
        6. Update knowledge graph
        """
        self.episode_count += 1

        logger.info(f"Starting episode {self.episode_count}")

        print(f"\n{'='*80}")
        print(f"Episode {self.episode_count}")
        print(f"{'='*80}\n")

        # RL: Start trace if enabled
        if self.rl_enabled:
            trace_id = self.rl_store.start_trace(
                agent_name="defender",
                episode_number=self.episode_count,
                metadata={"code_length": len(code_sample), "language": language}
            )
            self.defender.current_trace_id = trace_id
            logger.debug(f"Started RL trace: {trace_id}")

        # Phase 1: Defense
        print("🛡️  DEFENDER: Analyzing code...")
        defense_trace = self.defender.analyze(code_sample, language)
        print(f"   Found {len(defense_trace.findings)} potential vulnerabilities")
        print(f"   Time: {defense_trace.time_taken:.2f}s")

        # Phase 2: Attack original code
        print("\n⚔️  ATTACKER: Exploiting original code...")
        attack_original = self.attacker.attack(code_sample, language)
        print(f"   Found {len(attack_original.exploits)} exploitable vulnerabilities")
        print(f"   Success rate: {attack_original.success_rate:.1%}")
        print(f"   Time: {attack_original.time_taken:.2f}s")

        # Phase 3: Generate fixes
        fixed_code = code_sample
        if defense_trace.findings:
            print("\n🔧 DEFENDER: Generating fixes...")
            fixes = self.defender.suggest_fixes(
                defense_trace.findings,
                code_sample
            )
            if fixes:
                fixed_code = self.defender.apply_fixes(code_sample, fixes)
                print(f"   Generated {len(fixes)} fix(es)")
        else:
            print("\n🔧 DEFENDER: No fixes needed (no findings)")

        # Phase 4: Attack fixed code
        print("\n⚔️  ATTACKER: Testing fixed code...")
        attack_fixed = self.attacker.attack(fixed_code, language)
        print(f"   Found {len(attack_fixed.exploits)} exploitable vulnerabilities")
        print(f"   Success rate: {attack_fixed.success_rate:.1%}")
        print(f"   Time: {attack_fixed.time_taken:.2f}s")

        # Phase 5: Calculate metrics
        print("\n📊 EVALUATION:")
        metrics = self._calculate_metrics(
            defender_findings=defense_trace.findings,
            original_exploits=attack_original.exploits,
            fixed_exploits=attack_fixed.exploits
        )

        print(f"   True Positives: {metrics['true_positives']}")
        print(f"   False Positives: {metrics['false_positives']}")
        print(f"   False Negatives: {metrics['false_negatives']}")
        print(f"   Fixes that worked: {metrics['fixes_that_worked']}")
        print(f"   Fixes broken: {metrics['fixes_broken']}")
        print(f"   Novel exploit types: {metrics['novel_exploit_types']}")

        # Phase 6: Calculate rewards
        reward = self._calculate_reward(metrics, defense_trace.findings)
        attacker_reward = self._calculate_attacker_reward(metrics)

        # Calculate calibration score for display
        avg_brier = self._calculate_average_brier_score(defense_trace.findings)

        print(f"\n💰 DEFENDER REWARD: {reward:.2f}")
        if avg_brier is not None:
            print(f"   📊 Calibration (Brier): {avg_brier:.3f} (lower is better)")
        print(f"⚔️  ATTACKER REWARD: {attacker_reward:.2f}")

        # Phase 7: Update knowledge graph
        print("\n📚 LEARNING: Updating knowledge graph...")
        self._update_knowledge_graph(
            defender_findings=defense_trace.findings,
            attacker_exploits=attack_original.exploits
        )

        # Phase 8: RL reward emission and training
        if self.rl_enabled:
            # Emit reward
            self.rl_store.emit_reward(
                trace_id=self.defender.current_trace_id,
                reward=reward,
                metadata=metrics
            )

            # End trace
            self.rl_store.end_trace(self.defender.current_trace_id)
            self.defender.current_trace_id = None

            # Run training step if trainer is available
            if self.rl_trainer:
                training_metrics = self.rl_trainer.train_step(self.episode_count)
                if training_metrics:
                    logger.info(f"RL training step: {training_metrics}")
                    print(f"\n🤖 RL TRAINING: Applied update (improvement: {training_metrics.get('expected_improvement', 0):.3f})")

        # Create episode record
        episode = TrainingEpisode(
            episode_number=self.episode_count,
            code_sample=code_sample,
            language=language,
            defender_findings=defense_trace.findings,
            defense_time=defense_trace.time_taken,
            original_exploits=attack_original.exploits,
            fixed_exploits=attack_fixed.exploits,
            attack_time=attack_original.time_taken + attack_fixed.time_taken,
            reward=reward,
            attacker_reward=attacker_reward,
            true_positives=metrics['true_positives'],
            false_positives=metrics['false_positives'],
            false_negatives=metrics['false_negatives'],
            fixes_that_worked=metrics['fixes_that_worked'],
            fixes_broken=metrics['fixes_broken'],
            novel_exploit_types=metrics['novel_exploit_types'],
            timestamp=datetime.now()
        )

        # Save episode
        self._save_episode(episode)
        self.episodes.append(episode)

        return episode

    def _calculate_metrics(
        self,
        defender_findings: List[Finding],
        original_exploits: List[Exploit],
        fixed_exploits: List[Exploit]
    ) -> Dict:
        """Calculate training metrics"""

        # True positives: defender found AND attacker confirmed
        tp = 0
        for finding in defender_findings:
            for exploit in original_exploits:
                if self._matches(finding, exploit):
                    tp += 1
                    break

        # False positives: defender found but attacker couldn't exploit
        fp = len(defender_findings) - tp

        # False negatives: attacker found but defender missed
        fn = 0
        for exploit in original_exploits:
            found_by_defender = False
            for finding in defender_findings:
                if self._matches(finding, exploit):
                    found_by_defender = True
                    break
            if not found_by_defender:
                fn += 1

        # Fixes that worked: exploits blocked after fix
        fixes_worked = len(original_exploits) - len(fixed_exploits)

        # Fixes broken: exploits that still work after defender's fix
        fixes_broken = len(fixed_exploits)

        # Novel exploit types: exploit types never seen before
        current_exploit_types = {exploit.type for exploit in original_exploits}
        novel_types = current_exploit_types - self.seen_exploit_types
        novel_exploit_types = len(novel_types)

        # Update seen exploit types
        self.seen_exploit_types.update(current_exploit_types)

        return {
            "true_positives": tp,
            "false_positives": fp,
            "false_negatives": fn,
            "fixes_that_worked": fixes_worked,
            "fixes_broken": fixes_broken,
            "novel_exploit_types": novel_exploit_types
        }

    def _matches(self, finding: Finding, exploit: Exploit) -> bool:
        """Check if finding matches exploit"""
        # Match by CWE ID or type
        if finding.cwe_id and exploit.cwe_id:
            return finding.cwe_id == exploit.cwe_id

        # Fuzzy match by type
        finding_type = finding.type.lower().replace(" ", "_")
        exploit_type = exploit.type.lower()
        return finding_type == exploit_type

    def _calculate_average_brier_score(self, findings: List[Finding]) -> Optional[float]:
        """
        Calculate average Brier score for patterns used in findings.

        Returns:
            Average Brier score (0 = perfect calibration, 1 = worst), or None if no patterns tracked
        """
        brier_scores = []
        for finding in findings:
            if finding.pattern_id and finding.pattern_id in self.kg.patterns:
                pattern = self.kg.patterns[finding.pattern_id]
                if pattern.calibration_count > 0:  # Only include if we have calibration data
                    brier_scores.append(pattern.brier_score)

        if not brier_scores:
            return None

        return sum(brier_scores) / len(brier_scores)

    def _calculate_reward(self, metrics: Dict, findings: List[Finding]) -> float:
        """
        Calculate reward for this episode.

        Reward function (weights from config):
        - Reward true positives (correctly identified vulnerabilities)
        - Penalize false positives (wasted effort)
        - Heavily penalize false negatives (missed vulnerabilities)
        - Bonus for fixes that work
        - Bonus for well-calibrated predictions (low Brier score)
        """
        tp = metrics['true_positives']
        fp = metrics['false_positives']
        fn = metrics['false_negatives']
        fixes_worked = metrics['fixes_that_worked']

        # Base reward from detections and fixes
        base_reward = (
            self.reward_weights['true_positive'] * tp
            + self.reward_weights['false_positive'] * fp  # Already negative in config
            + self.reward_weights['false_negative'] * fn   # Already negative in config
            + self.reward_weights['fix_worked'] * fixes_worked
        )

        # Calibration bonus: reward well-calibrated confidence predictions
        calibration_bonus = 0.0
        avg_brier = self._calculate_average_brier_score(findings)
        if avg_brier is not None:
            # Brier score: 0 = perfect, 1 = worst
            # Bonus = weight * (1 - brier_score), so perfect calibration gets full bonus
            calibration_bonus = self.reward_weights['calibration_bonus_weight'] * (1.0 - avg_brier)

        reward = base_reward + calibration_bonus

        return reward

    def _calculate_attacker_reward(self, metrics: Dict) -> float:
        """
        Calculate reward for the attacker agent.

        Attacker reward function (creates adversarial pressure):
        - Reward finding vulnerabilities defender missed (false negatives)
        - Penalty for being detected (true positives)
        - High reward for breaking defender's fixes (fixes_broken)
        - Bonus for discovering novel exploit types

        This creates strong adversarial pressure on the defender.
        """
        fn = metrics['false_negatives']
        tp = metrics['true_positives']
        fixes_broken = metrics['fixes_broken']
        novel_types = metrics['novel_exploit_types']

        # Use weights from config
        attacker_reward = (
            self.attacker_reward_weights['false_negatives'] * fn
            + self.attacker_reward_weights['true_positives'] * tp  # Already negative in config
            + self.attacker_reward_weights['fixes_broken'] * fixes_broken
            + self.attacker_reward_weights['novel_exploits'] * novel_types
        )

        return attacker_reward

    def _update_knowledge_graph(
        self,
        defender_findings: List[Finding],
        attacker_exploits: List[Exploit]
    ):
        """Update pattern effectiveness based on attacker feedback"""

        # Update patterns that defender used
        for finding in defender_findings:
            if finding.pattern_id:
                # Check if this was a true positive
                is_tp = any(
                    self._matches(finding, exploit)
                    for exploit in attacker_exploits
                )

                # Update effectiveness with calibration tracking
                self.kg.update_pattern_effectiveness(
                    pattern_id=finding.pattern_id,
                    is_true_positive=is_tp,
                    is_false_negative=False,
                    confidence=finding.confidence  # Track calibration
                )

        # Check for false negatives (attacker found but defender missed)
        for exploit in attacker_exploits:
            found_by_defender = any(
                self._matches(finding, exploit)
                for finding in defender_findings
            )

            if not found_by_defender:
                # This was a false negative
                # Find the pattern that should have caught it
                pattern_id = self._find_pattern_for_exploit(exploit)
                if pattern_id:
                    self.kg.update_pattern_effectiveness(
                        pattern_id=pattern_id,
                        is_true_positive=False,
                        is_false_negative=True
                    )

    def _find_pattern_for_exploit(self, exploit: Exploit) -> Optional[str]:
        """Find pattern ID that should have detected this exploit"""
        # Map exploit types to patterns
        exploit_to_pattern = {
            "sql_injection": "PATTERN-SQL-001",
            "xss": "PATTERN-XSS-001",
            "command_injection": "PATTERN-CMD-001",
            "path_traversal": "PATTERN-PATH-001",
        }

        return exploit_to_pattern.get(exploit.type)

    def _save_episode(self, episode: TrainingEpisode):
        """Save episode to disk"""
        filename = f"episode_{episode.episode_number:04d}.json"
        filepath = self.episodes_dir / filename

        with open(filepath, 'w') as f:
            json.dump(episode.to_dict(), f, indent=2, default=str)

    def get_learning_progress(self) -> Dict:
        """Get metrics showing learning progress"""
        if not self.episodes:
            return {"status": "no_data"}

        # Calculate metrics over time
        recent_window = min(10, len(self.episodes))
        recent_episodes = self.episodes[-recent_window:]

        early_window = min(10, len(self.episodes))
        early_episodes = self.episodes[:early_window]

        def avg_metric(episodes, metric):
            return sum(getattr(e, metric) for e in episodes) / len(episodes)

        recent_reward = avg_metric(recent_episodes, 'reward')
        early_reward = avg_metric(early_episodes, 'reward')

        recent_tp_rate = avg_metric(recent_episodes, 'true_positives')
        recent_fp_rate = avg_metric(recent_episodes, 'false_positives')

        return {
            "total_episodes": len(self.episodes),
            "early_avg_reward": early_reward,
            "recent_avg_reward": recent_reward,
            "improvement": recent_reward - early_reward,
            "improvement_pct": ((recent_reward - early_reward) / abs(early_reward) * 100)
                if early_reward != 0 else 0,
            "recent_true_positives": recent_tp_rate,
            "recent_false_positives": recent_fp_rate,
            "knowledge_graph_stats": self.kg.get_stats()
        }


if __name__ == "__main__":
    # Test self-play trainer
    import os

    if os.getenv("ANTHROPIC_API_KEY"):
        from src.knowledge.graph import SecurityKnowledgeGraph
        from src.agents.defender import DefenderAgent
        from src.agents.attacker import AttackerAgent

        # Create components
        kg = SecurityKnowledgeGraph()
        defender = DefenderAgent(kg)
        attacker = AttackerAgent()

        # Create trainer
        trainer = SelfPlayTrainer(kg, defender, attacker)

        # Test code sample
        vulnerable_code = '''
def login(username, password):
    query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
    result = db.execute(query)
    return result
'''

        # Run episode
        episode = trainer.train_episode(vulnerable_code, "python")

        print(f"\n{'='*80}")
        print("EPISODE SUMMARY")
        print(f"{'='*80}")
        print(f"Reward: {episode.reward:.2f}")
        print(f"True Positives: {episode.true_positives}")
        print(f"False Positives: {episode.false_positives}")
        print(f"False Negatives: {episode.false_negatives}")
        print(f"Fixes that worked: {episode.fixes_that_worked}")

        # Show progress
        progress = trainer.get_learning_progress()
        print(f"\nLearning Progress:")
        print(json.dumps(progress, indent=2))

    else:
        print("Set ANTHROPIC_API_KEY to test self-play trainer")
