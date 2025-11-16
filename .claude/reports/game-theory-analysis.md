# Game-Theoretic Analysis of ASDS Self-Play System

**Date:** November 16, 2025
**Agent:** Game Theory Expert
**System Analyzed:** ASDS Self-Play v2

## Executive Summary

The ASDS self-play reward function has **significant strategic vulnerabilities** that enable gaming and misaligned incentives. The analysis reveals asymmetric penalties creating over-reporting bias, fix rewards too high relative to detection, and no attacker incentives creating no adversarial pressure.

**Critical Issues:**
- 🔴 Over-reporting bias (FP penalty too low)
- 🔴 Fix inflation (fix reward 2× detection reward)
- 🔴 No attacker reward function
- 🟠 No calibration incentives
- 🟠 Single-objective optimization enables gaming

**Recommended Solutions:**
- Rebalanced weights with 2.4× higher FP penalty
- Adversarial reward function for attacker
- Calibration bonuses via Brier scoring
- Exploration and diversity incentives

## Current Game Structure

### Players
- **Defender:** Security analysis agent
- **Attacker:** Exploit generation agent

### Current Reward Function
```python
reward = (
    10.0 * true_positives     # Detection value
    - 5.0 * false_positives   # False alarm cost
    - 15.0 * false_negatives  # Missed vulnerability cost
    + 20.0 * fixes_worked     # Working fix value
)
```

### Strategic Issues

**Defender Gaming Opportunities:**
1. **Shotgun Strategy:** Report everything at low confidence (FP penalty < FN penalty)
2. **Fix Theater:** Report primarily to claim fix rewards (20 > 10)
3. **Pattern Manipulation:** Only use proven patterns (avoid exploration)

**Attacker Limitations:**
- No explicit reward function
- Operates deterministically
- No incentive to improve or explore

## Nash Equilibrium Analysis

**Current Equilibrium:** Defender over-reports uncertain findings

**Mathematical Analysis:**
```
p* = (β × w_fn) / (β × w_fn + (1-α) × w_fp)
p* = (β × 15) / (β × 15 + (1-α) × 5)
p* ≈ 0.75 with β ≈ 0.3, α ≈ 0.7
```

**Result:** Defender should report ~75% of uncertain findings, creating systematic over-reporting bias.

## Recommended Improvements

### 1. Rebalanced Weights
```python
# Recommended Version A: Balanced Precision
w_tp = 15.0   # ↑ from 10.0
w_fp = 12.0   # ↑↑ from 5.0 (2.4× increase)
w_fn = 18.0   # ↑ from 15.0
w_fix = 15.0  # ↓ from 20.0
```

### 2. Attacker Reward Function
```python
attacker_reward = (
    15.0 * false_negatives      # Found what defender missed
    - 5.0 * true_positives      # Penalty for being detected
    + 25.0 * fixes_broken       # High value for breaking fixes
    + 10.0 * novel_exploits     # Bonus for creativity
)
```

### 3. Calibration Bonuses
```python
# Brier score for confidence calibration
calibration_bonus = 10.0 * (1.0 - avg_brier_score)
```

### 4. Exploration Incentives
```python
exploration_bonus = (
    5.0 * low_observation_patterns +  # Try new patterns
    15.0 * novel_vulnerability_types  # Discover new types
)
```

## Predicted Outcomes

**If recommendations implemented:**
- Precision: +15-25% improvement
- Recall: Maintained or slight increase
- Pattern Diversity: +40% more pattern types
- Learning Speed: 2-3× faster via adversarial pressure
- Fix Quality: Measurable improvement

## Experimental Recommendations

1. **A/B Test Weight Configurations**
2. **Test Adversarial vs Non-Adversarial Rewards**
3. **Measure Exploration Impact**
4. **Robustness Testing Against Gaming**

See full analysis in comprehensive report for detailed mathematical formulations and experimental designs.
