#!/bin/bash
# push.sh — stage, commit, and push changes to GitHub
# Usage: bash push.sh "your commit message"
# Example: bash push.sh "Add regex practice script"

# Check a commit message was passed in
if [ -z "$1" ]; then
    echo "Usage: bash push.sh \"your commit message\""
    exit 1
fi

# Show what files have changed before staging
echo ""
echo "=== Changed files ==="
git status --short
echo ""

# Stage everything except files in .gitignore
git add \
    python/scripts/ \
    python/practice/ \
    python/datasets/ \
    notes/ \
    bash/ \
    sigma/ \
    yaml/ \
    powershell/ \
    docker/ \
    CLAUDE.md

# Commit with the message passed as an argument
git commit -m "$1"

# Push to GitHub
git push origin master

echo ""
echo "Done. Check your repo on GitHub."
