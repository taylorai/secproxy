#!/usr/bin/env bash
# Reuse the pinned remote Gitleaks hook's environment, but scan outgoing
# commits instead of the normally empty staging area at push time.
set -euo pipefail

to_ref="${PRE_COMMIT_TO_REF:-}"
from_ref="${PRE_COMMIT_FROM_REF:-}"
if [[ -z "$to_ref" ]]; then
  echo "Gitleaks pre-push requires a push range. For a manual scan, use prek run gitleaks-pre-push --hook-stage pre-push --from-ref BASE --to-ref HEAD." >&2
  exit 2
fi

# Resolve refs to commit IDs before passing them through Gitleaks's log-opts
# parser. Invalid/missing objects must fail rather than silently skip scanning.
to_commit="$(git rev-parse --verify --end-of-options "${to_ref}^{commit}")"
if [[ -n "$from_ref" ]]; then
  from_commit="$(git rev-parse --verify --end-of-options "${from_ref}^{commit}")"
  scan_range="${from_commit}..${to_commit}"
else
  # First push of a repository (or unrelated root): prek supplies only TO_REF.
  # Include its complete reachable history, including the root commit.
  scan_range="$to_commit"
fi

# Scan each commit's additions, including merge resolutions and secrets later
# removed in the same push. No --staged, net diff, first-parent, or file filter.
exec gitleaks git --redact --no-banner \
  --log-opts="--full-history --root -m --no-ext-diff --no-textconv $scan_range" .
