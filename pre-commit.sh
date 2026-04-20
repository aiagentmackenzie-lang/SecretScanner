#!/bin/bash
# SecretScanner pre-commit hook
# Place this file in .git/hooks/pre-commit (without .sh extension)
# and make it executable: chmod +x .git/hooks/pre-commit

set -e

echo "Running SecretScanner pre-commit hook..."

# Get the repository root
REPO_ROOT=$(git rev-parse --show-toplevel)
cd "$REPO_ROOT"

# Check if secretscanner binary exists
if [ -f "./secretscanner" ]; then
    SCANNER="./secretscanner"
elif command -v secretscanner >/dev/null 2>&1; then
    SCANNER="secretscanner"
else
    echo "Error: secretscanner not found. Build it with: go build ./cmd/secretscanner"
    exit 1
fi

# Get list of staged files
STAGED_FILES=$(git diff --cached --name-only --diff-filter=ACM)

if [ -z "$STAGED_FILES" ]; then
    echo "No staged files to scan."
    exit 0
fi

# Scan each staged file
echo "Scanning staged files for secrets..."
FOUND_SECRETS=0

for file in $STAGED_FILES; do
    # Skip binary and large files
    if [ -f "$file" ]; then
        # Skip based on extension
        if [[ "$file" =~ \.(jpg|jpeg|png|gif|pdf|doc|docx|xls|xlsx|zip|tar|gz|exe|dll|so|dylib)$ ]]; then
            continue
        fi
        
        # Run scan on individual file
        if ! "$SCANNER" scan "$file" --severity high,critical --fail-on-findings 2>/dev/null; then
            echo "⚠️  Potential secret found in: $file"
            FOUND_SECRETS=1
        fi
    fi
done

if [ $FOUND_SECRETS -eq 1 ]; then
    echo ""
    echo "=========================================="
    echo "❌ COMMIT BLOCKED"
    echo "=========================================="
    echo ""
    echo "Potential secrets detected in staged files."
    echo "Please review and remove secrets before committing."
    echo ""
    echo "To bypass this check (NOT RECOMMENDED):"
    echo "  git commit --no-verify"
    echo ""
    echo "To mark as false positive, add comment to line:"
    echo "  // secretscanner:allow"
    echo "  # secretscanner:allow"
    echo "=========================================="
    exit 1
fi

echo "✅ No secrets detected in staged files."
exit 0
