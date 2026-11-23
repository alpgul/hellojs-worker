#!/usr/bin/env bash
# Lift local commits from the base branch into an AI-named branch and open a PR.
# Phase 1: PR creation only. No approve, no merge, no auto-merge, no pull.
set -euo pipefail

REMOTE="${LIFT_REMOTE:-origin}"
BASE="${LIFT_BASE:-worker}"
PREFIX="${LIFT_PREFIX:-ai}"
MODEL="${LIFT_MODEL:-kilo/kilo-auto/free}"

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
PROMPT_FILE="$SCRIPT_DIR/prompts/pr-metadata.txt"

cd "$(git rev-parse --show-toplevel)"

CURRENT="$(git branch --show-current)"
if [[ "$CURRENT" != "$BASE" ]]; then
  echo "error: run this from '$BASE' (currently on '$CURRENT')" >&2
  exit 1
fi

if ! git diff --quiet || ! git diff --cached --quiet; then
  echo "error: working tree is dirty; commit or stash first" >&2
  exit 1
fi

REPO="$(gh repo view --json nameWithOwner --jq .nameWithOwner)"
git fetch "$REMOTE" "$BASE" --quiet

COMMIT_COUNT="$(git rev-list --count "$REMOTE/$BASE..$BASE")"
if [[ "$COMMIT_COUNT" -eq 0 ]]; then
  echo "no new commits on $BASE; nothing to do"
  exit 0
fi

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

# Build a bounded diff for the AI prompt. Lockfiles, build output and coverage
# are excluded; the patch is truncated to keep the prompt small.
{
  echo "=== COMMITS ==="
  git log --reverse --format='%h %s' "$REMOTE/$BASE..$BASE"
  echo
  echo "=== DIFF STAT ==="
  git diff --stat "$REMOTE/$BASE" "$BASE" -- \
    . \
    ':(exclude)package-lock.json' \
    ':(exclude)pnpm-lock.yaml' \
    ':(exclude)yarn.lock' \
    ':(exclude)dist/**' \
    ':(exclude)coverage/**'
  echo
  echo "=== PATCH (truncated) ==="
  git diff --no-ext-diff --unified=1 "$REMOTE/$BASE" "$BASE" -- \
    . \
    ':(exclude)package-lock.json' \
    ':(exclude)pnpm-lock.yaml' \
    ':(exclude)yarn.lock' \
    ':(exclude)dist/**' \
    ':(exclude)coverage/**' > "$TMP/patch.full"
  head -c 20000 "$TMP/patch.full"
} > "$TMP/changes.txt"

echo "asking $MODEL for PR metadata ($COMMIT_COUNT commit(s))..."
opencode run \
  --model "$MODEL" \
  --format json \
  --auto \
  --archived \
  --file "$TMP/changes.txt" \
  "$(cat "$PROMPT_FILE")" > "$TMP/ai.out"

# Parse and strictly validate the AI output. On any failure, fall back to a
# deterministic metadata set derived from the latest commit.
if ! python3 - "$TMP/ai.out" "$TMP" <<'PY'
import json
import pathlib
import re
import sys

out_path = pathlib.Path(sys.argv[1])
tmp = pathlib.Path(sys.argv[2])
text = out_path.read_text(errors="replace")

def parse_metadata(raw):
    variants = [raw]
    variants.extend(
        m.group(1) for m in re.finditer(r"```(?:json)?\s*(.*?)```", raw, re.S | re.I)
    )
    variants.extend(m.group(0) for m in re.finditer(r"\{.*?\}", raw, re.S))
    for variant in variants:
        variant = variant.strip()
        if not variant:
            continue
        try:
            candidate = json.loads(variant)
        except Exception:
            continue
        if isinstance(candidate, dict) and {"branch", "title", "body"} <= candidate.keys():
            return candidate
    return None


obj = None
# --format json emits one event per line; the model message lives in part.text.
for line in text.splitlines():
    line = line.strip()
    if not line:
        continue
    try:
        event = json.loads(line)
    except Exception:
        continue
    part = event.get("part") if isinstance(event, dict) else None
    if isinstance(part, dict) and part.get("type") == "text":
        obj = parse_metadata(part.get("text", ""))
        if obj is not None:
            break

if obj is None:
    obj = parse_metadata(text)
if obj is None:
    sys.exit("AI_JSON_PARSE_FAILED")


def ascii_str(value, maxlen=None):
    if not isinstance(value, str):
        return None
    value = value.strip()
    if not value or not value.isascii():
        return None
    if maxlen is not None and len(value) > maxlen:
        return None
    return value


branch = ascii_str(obj["branch"], 40)
if branch is None or not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,38}[a-z0-9])?", branch):
    sys.exit("BRANCH_INVALID")

title = ascii_str(obj["title"], 72)
if title is None or "\n" in title:
    sys.exit("TITLE_INVALID")

body = ascii_str(obj["body"])
if body is None:
    sys.exit("BODY_INVALID")

(tmp / "branch").write_text(branch)
(tmp / "title").write_text(title)
(tmp / "body.md").write_text(body + "\n")
PY
then
  echo "AI metadata invalid; using fallback" >&2
  SUBJECT="$(git log -1 --format=%s)"
  SLUG="$(printf '%s' "$SUBJECT" | LC_ALL=C tr -cd 'A-Za-z0-9 -' \
    | tr '[:upper:]' '[:lower:]' | tr -s ' -' '-' \
    | sed 's/^-//; s/-$//' | cut -c1-40)"
  [[ -n "$SLUG" ]] || SLUG="auto-pr-$(git rev-parse --short HEAD)"
  printf '%s' "$SLUG" > "$TMP/branch"
  printf 'chore: automated PR' > "$TMP/title"
  printf '## Summary\nAutomated pull request.\n' > "$TMP/body.md"
fi

SLUG="$(cat "$TMP/branch")"
TITLE="$(cat "$TMP/title")"
BRANCH="$PREFIX/$SLUG"

if git ls-remote --exit-code --heads "$REMOTE" "$BRANCH" >/dev/null 2>&1; then
  BRANCH="$BRANCH-$(git rev-parse --short HEAD)"
fi

if [[ "${LIFT_DRY_RUN:-0}" == "1" ]]; then
  echo "DRY RUN - no branch, push or PR created"
  echo "Would create head branch: $BRANCH"
  echo "PR title: $TITLE"
  echo "PR body:"
  cat "$TMP/body.md"
  exit 0
fi

git branch "$BRANCH" "$BASE"
git push -u "$REMOTE" "$BRANCH" --quiet

gh label create auto-pr --repo "$REPO" \
  --color 0E8A16 --description "Automatically generated PR" --force \
  >/dev/null 2>&1 || true

PR_URL="$(
  gh pr create \
    --repo "$REPO" \
    --base "$BASE" \
    --head "$BRANCH" \
    --title "$TITLE" \
    --body-file "$TMP/body.md" \
    --label auto-pr
)"
PR_URL="$(printf '%s\n' "$PR_URL" | tail -n 1)"
if [[ ! "$PR_URL" =~ ^https:// ]]; then
  echo "error: unexpected PR output: $PR_URL" >&2
  exit 1
fi

PR_NUMBER="${PR_URL##*/}"
if [[ ! "$PR_NUMBER" =~ ^[0-9]+$ ]]; then
  echo "error: could not determine PR number from $PR_URL" >&2
  exit 1
fi

echo "Enabling rebase auto-merge for PR #$PR_NUMBER..."
gh pr merge "$PR_NUMBER" --repo "$REPO" --auto --rebase

# With no required checks the merge can complete immediately, so refresh the
# remote-tracking ref before rewinding the local base branch.
git fetch "$REMOTE" "$BASE" --quiet
git reset --hard "$REMOTE/$BASE" --quiet

echo "PR created: $PR_URL"
echo "Head branch: $BRANCH"
echo "Rebase auto-merge enabled"
echo "Local $BASE reset to $REMOTE/$BASE"
