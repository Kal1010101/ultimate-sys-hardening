#!/bin/bash
# Point this clone's hooks at the tracked scripts/hooks/ directory.
#
# The hook lives in the repository rather than in .git/hooks so that it is
# reviewable, testable and survives a re-clone. .git/hooks is not version
# controlled, so a guard that lives only there protects exactly one checkout —
# and the leak this guards against happened on a machine that had every other
# protection in place.
#
# core.hooksPath is per-clone config, so this has to be run once per clone.
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/../.."
git rev-parse --git-dir >/dev/null 2>&1 || { echo "Not a git repository." >&2; exit 1; }

git config core.hooksPath scripts/hooks
echo "hooks: core.hooksPath -> scripts/hooks"
echo "       pre-commit will refuse commercial source in this public repo."
echo
echo "Verify it works:  bash tests/cases/test_publication_guard.sh"
