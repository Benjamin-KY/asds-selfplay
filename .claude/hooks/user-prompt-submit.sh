#!/bin/bash
# User Prompt Submit Hook
# Invoked whenever the user submits a prompt

# Extract the user's message
USER_MESSAGE="$1"

# Invoke Game Theory Agent for strategic analysis
if echo "$USER_MESSAGE" | grep -iE "reward|strategy|equilibrium|game|incentive|payoff" > /dev/null; then
    echo "🎮 [Game Theory Agent] Analyzing strategic implications..."
    # Game theory agent will be automatically invoked via skill
fi

# Invoke Compliance Agent for documentation review
if echo "$USER_MESSAGE" | grep -iE "commit|push|change|update|modify|audit|compliance|document" > /dev/null; then
    echo "📋 [Compliance Agent] Checking documentation and audit trail..."
    # Compliance agent will be automatically invoked via skill
fi

# Invoke Research Agent for hypothesis testing
if echo "$USER_MESSAGE" | grep -iE "research|paper|benchmark|dataset|compare|hypothesis|test|validate|prior.*art" > /dev/null; then
    echo "🔬 [Research Agent] Searching for relevant research..."
    # Research agent will be automatically invoked via skill
fi

# Always invoke agents for major operations
if echo "$USER_MESSAGE" | grep -iE "build|implement|create|design|train|episode" > /dev/null; then
    echo "🎮 [Game Theory Agent] Analyzing game-theoretic implications..."
    echo "📋 [Compliance Agent] Ensuring proper documentation..."
    echo "🔬 [Research Agent] Checking for relevant prior work..."
fi

# Exit successfully to allow the prompt to proceed
exit 0
