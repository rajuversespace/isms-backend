#!/usr/bin/env bash
# =============================================================================
# Setup script: Install gitleaks + configure pre-commit hook
#
# Usage: ./scripts/setup-hooks.sh
# =============================================================================

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
HOOKS_DIR="$REPO_ROOT/.git/hooks"
HOOK_SOURCE="$REPO_ROOT/scripts/pre-commit"
HOOK_DEST="$HOOKS_DIR/pre-commit"

echo -e "${YELLOW}ISMS Backend — Security Hooks Setup${NC}"
echo "======================================"
echo ""

# ---------- 1. Install gitleaks ----------
echo -e "${YELLOW}[1/3]${NC} Checking for gitleaks..."

if command -v gitleaks &> /dev/null; then
    GITLEAKS_VERSION=$(gitleaks version 2>/dev/null || echo "unknown")
    echo -e "${GREEN}  gitleaks already installed (${GITLEAKS_VERSION})${NC}"
else
    echo "  gitleaks not found. Installing..."

    if [[ "$OSTYPE" == "darwin"* ]]; then
        if command -v brew &> /dev/null; then
            brew install gitleaks
        else
            echo -e "${RED}  Homebrew not found. Install gitleaks manually:${NC}"
            echo "    https://github.com/gitleaks/gitleaks#installing"
            echo ""
            echo "  Continuing with fallback pattern scanner..."
        fi
    elif [[ "$OSTYPE" == "linux-gnu"* ]]; then
        # Try to install via package manager or download binary
        if command -v apt-get &> /dev/null; then
            echo "  Downloading gitleaks binary..."
            GITLEAKS_VERSION="8.18.4"
            curl -sSfL "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_linux_x64.tar.gz" \
                | tar -xz -C /usr/local/bin gitleaks 2>/dev/null || {
                echo -e "${YELLOW}  Could not install to /usr/local/bin (needs sudo).${NC}"
                echo "  Install manually: https://github.com/gitleaks/gitleaks#installing"
            }
        fi
    else
        echo -e "${YELLOW}  Unsupported OS. Install gitleaks manually:${NC}"
        echo "    https://github.com/gitleaks/gitleaks#installing"
    fi

    if command -v gitleaks &> /dev/null; then
        echo -e "${GREEN}  gitleaks installed successfully.${NC}"
    fi
fi

# ---------- 2. Install the pre-commit hook ----------
echo ""
echo -e "${YELLOW}[2/3]${NC} Installing pre-commit hook..."

# Copy the hook from scripts/ to .git/hooks/
cp "$REPO_ROOT/scripts/pre-commit" "$HOOK_DEST"
chmod +x "$HOOK_DEST"
echo -e "${GREEN}  Pre-commit hook installed at: .git/hooks/pre-commit${NC}"

# ---------- 3. Verify ----------
echo ""
echo -e "${YELLOW}[3/3]${NC} Verifying setup..."

if [ -x "$HOOK_DEST" ]; then
    echo -e "${GREEN}  Pre-commit hook is executable.${NC}"
else
    echo -e "${RED}  ERROR: Pre-commit hook is not executable.${NC}"
    exit 1
fi

if command -v gitleaks &> /dev/null; then
    echo -e "${GREEN}  gitleaks is available.${NC}"
    echo ""
    echo -e "  Running a quick scan of the repo..."
    if gitleaks detect --source="$REPO_ROOT" --config="$REPO_ROOT/.gitleaks.toml" --verbose 2>&1; then
        echo -e "${GREEN}  No secrets found in the repository.${NC}"
    else
        echo -e "${RED}  Secrets found! Please review and remove them.${NC}"
    fi
else
    echo -e "${YELLOW}  gitleaks not available — fallback pattern scanner will be used.${NC}"
fi

echo ""
echo "======================================"
echo -e "${GREEN}Setup complete!${NC}"
echo ""
echo "What happens now:"
echo "  - Every 'git commit' will scan staged files for secrets"
echo "  - If a secret is found, the commit is BLOCKED"
echo "  - GitHub Actions will also scan on push/PR (belt + suspenders)"
echo ""
echo "To skip the hook (NOT recommended):"
echo "  git commit --no-verify"
echo ""
