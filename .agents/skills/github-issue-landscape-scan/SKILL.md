---
name: github-issue-landscape-scan
description: "Use when asked what features a GitHub project's issues/PRs/forks are actively developing vs already complete; use GitHub REST via curl when gh is absent"
---

# Scan a GitHub repo's issue/PR/feature landscape

Goal: answer "what is others developing vs what is done" from real data, not the issue titles alone.

## Steps
1. Confirm remote: `git remote -v`, `git log -5 --date=short`, `git tag --sort=-creatordate` for local reality.
2. API instead of `gh` (often not installed):
   - `curl -s -m 30 "https://api.github.com/repos/<o>/<r>/issues?state=open&per_page=100&page=N"` — paginate until empty; issues and PRs are mixed (`pull_request` key distinguishes).
   - `.../pulls?state=all&per_page=100&sort=updated&direction=desc` for merged/unmerged history.
   - Repo meta gives `open_issues_count` (includes PRs) → sanity-check your tally.
3. Read bodies/comments of the few substantive threads: `.../issues/<n>` and `.../issues/<n>/comments`. Maintainer stance and design blockers live in comments, not titles.
4. Find work not yet PR'ed: `.../repos/<o>/<r>/branches`, then for each contributor `.../repos/<user>/<r>/branches`. Branch names often reveal features (`debug-support`, `feature/macho-object-*`, `ant/gc`). Get head dates via `.../branches/<name>` (URL-encode `/` as `%2F`).
5. Detect stale vs active: compare branch/PR `updated_at` to `pushed_at` and recent master commits; a 2021 PR open today is abandoned, not "in development".
6. Cross-check issue status against merged PRs — an issue may be fixed but left open (search PR bodies for the issue number); state that explicitly.

## Windows/PowerShell gotchas (important)
- `/tmp` does not exist for curl output; write JSON into the repo cwd, then delete all temp files and confirm `git status --short` is clean before reporting.
- Decode JSON explicitly: `json.load(f, encoding='utf-8')` — Python's default GBK fails on UTF-8 bodies.
- Prefer `python` (`eval`) for parsing/aggregation over shell one-liners; use `curl` + files, not pipes.

## Output shape
- Lead with status counts and whether the project is maintainer-driven or community-driven.
- Table: open PRs (author, content, real status/staleness).
- Table: fork branches = features under development, with date + scope.
- Table: design-stage issues and their blockers.
- Table: completed work grouped by subsystem, cite PR numbers, note mature vs missing capabilities.
- Label unverified inferences as `[INFERENCE]`; never present an open issue as unimplemented without checking the code tree (e.g. `mir-gen-*.c` presence proves a backend exists).
