#!/usr/bin/env bash
# Publish a report-only commit without overwriting a newer research branch.
set -euo pipefail
branch='research/battlenet-minimal-install-isolation-2026-10-25'
report_dir='reports/minimal-install-c1b'
if [[ -n "$(git status --porcelain)" ]]; then
  echo 'Refusing publication from a dirty worktree' >&2; exit 1
fi
report_commit=$(git rev-parse HEAD)
if git diff-tree --no-commit-id --name-only -r "$report_commit" | grep -qv "^${report_dir}/"; then
  echo 'Refusing a commit containing non-report changes' >&2; exit 1
fi
for attempt in 1 2 3; do
  git fetch --no-tags origin "refs/heads/$branch"
  git checkout --detach FETCH_HEAD
  # A conflicting/newer report is not silently replaced.
  if ! git cherry-pick "$report_commit"; then
    git cherry-pick --abort
    echo 'Report conflict or already-published batch; no overwrite attempted' >&2
    exit 1
  fi
  if git push origin "HEAD:refs/heads/$branch"; then exit 0; fi
  echo "Branch advanced during publication (attempt $attempt); refetching" >&2
done
echo 'Publication retries exhausted; sanitized artifact remains available' >&2
exit 1
