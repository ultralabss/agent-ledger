#!/usr/bin/env bash
# Seeds a throwaway ledger with demo data for a local visual check of the web
# UI. NEVER point LEDGER_DIR at ~/.ledger — this script writes and
# mutates whatever directory it is given. Idempotent-ish: re-running against
# the same dir just adds more of the same shapes (fine for a demo ledger you
# wipe between runs).
#
# Usage:
#   LEDGER_DIR=$(mktemp -d) LEDGER_HUB_PORT=4799 packages/web/scripts/seed-demo.sh
#
# Prints the hub URL and how to log in (never the token) at the end.

set -euo pipefail

: "${LEDGER_DIR:?set LEDGER_DIR to a scratch dir, never ~/.ledger}"
: "${LEDGER_HUB_PORT:=4799}"

# Safety guard: refuse the real ledger dir (trailing slash, relative parts,
# symlinks; checked before anything is created).
_norm() {
  local p="${1%/}" d
  d="$(cd "$(dirname "$p")" 2>/dev/null && pwd -P)" || d="$(dirname "$p")"
  printf '%s/%s' "${d%/}" "$(basename "$p")"
}
if [ "$(_norm "$LEDGER_DIR")" = "$(_norm "$HOME/.ledger")" ]; then
  echo "refusing to seed ~/.ledger — use a scratch dir (e.g. LEDGER_DIR=\$(mktemp -d))" >&2
  exit 1
fi
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"

mkdir -p "$LEDGER_DIR"

echo "== starting hub on :$LEDGER_HUB_PORT against $LEDGER_DIR" >&2
LEDGER_DIR="$LEDGER_DIR" LEDGER_HUB_PORT="$LEDGER_HUB_PORT" LEDGER_PUSH=0 LEDGER_INTRUDE=1 \
  node "$ROOT/packages/hub/src/bin.ts" >"$LEDGER_DIR/hub.stdout.log" 2>&1 &
HUB_PID=$!
trap 'kill "$HUB_PID" 2>/dev/null || true' EXIT

# Wait for the token file + a healthy /v1/healthz.
for _ in $(seq 1 50); do
  [ -f "$LEDGER_DIR/.hub/token" ] && break
  sleep 0.1
done
TOKEN="$(cat "$LEDGER_DIR/.hub/token")"
BASE="http://127.0.0.1:$LEDGER_HUB_PORT"

# Never put the token on a curl command line — it lands verbatim in `ps`
# for any other local user to read. `curl -K -` takes the header from stdin
# via a config line instead, so the token never appears as an argv entry.
curl_auth() {
  printf 'header = "X-Hub-Token: %s"\n' "$TOKEN" | curl -sf -K - "$@"
}

for _ in $(seq 1 50); do
  curl_auth "$BASE/v1/healthz" >/dev/null && break
  sleep 0.1
done

api() {
  local method="$1" path="$2" body="${3:-}"
  if [ -n "$body" ]; then
    curl_auth -X "$method" -H 'content-type: application/json' -d "$body" "$BASE$path"
  else
    curl_auth -X "$method" "$BASE$path"
  fi
}

echo "== repos" >&2
api POST /v1/repos '{"slug":"acme-shop","prefix":"ACME","path":null}' >/dev/null
api POST /v1/repos '{"slug":"web","prefix":"WEB","path":null}' >/dev/null
api POST /v1/repos '{"slug":"api","prefix":"API","path":null}' >/dev/null
api POST /v1/repos '{"slug":"mobile","prefix":"MOB","path":null}' >/dev/null

echo "== items" >&2
ITEM1=$(api POST /v1/items '{"repo":"acme-shop","title":"Deploy the payment gateway","kind":"DEPLOY","priority":"P0","owner":"human","why":"Blocks the 1.0 release.","rec":"AUTHORIZED: deploy after review\nCheck the webhook secret before pushing.","steps":["verify webhook secret","run the migration","deploy"]}' | node -e "process.stdin.on('data',d=>process.stdout.write(JSON.parse(d).id))")
ITEM2=$(api POST /v1/items '{"repo":"acme-shop","title":"Fix flaky CI test","kind":"RISK","priority":"P1","owner":"agent","why":"test fails in ~1 of 10 runs","rec":"Add a retry or find the race."}' | node -e "process.stdin.on('data',d=>process.stdout.write(JSON.parse(d).id))")
ITEM3=$(api POST /v1/items '{"repo":"acme-shop","title":"Document API keys","kind":"UNVERIFIED","priority":"P2","owner":"human","status":"doing"}' | node -e "process.stdin.on('data',d=>process.stdout.write(JSON.parse(d).id))")
ITEM4=$(api POST /v1/items '{"repo":"acme-shop","title":"Clean up old logs","kind":"BACKLOG","priority":"P3","owner":"agent"}' | node -e "process.stdin.on('data',d=>process.stdout.write(JSON.parse(d).id))")
ITEM5=$(api POST /v1/items '{"repo":"web","title":"Migrate the DB schema","kind":"BLOCKER","priority":"P0","owner":"human","status":"blocked"}' | node -e "process.stdin.on('data',d=>process.stdout.write(JSON.parse(d).id))")
ITEM6=$(api POST /v1/items '{"repo":"web","title":"Add rate limiting","kind":"RISK","priority":"P1","owner":"agent","status":"doing"}' | node -e "process.stdin.on('data',d=>process.stdout.write(JSON.parse(d).id))")
ITEM7=$(api POST /v1/items '{"repo":"web","title":"Onboarding flow","kind":"BACKLOG","priority":"P2","owner":"human"}' | node -e "process.stdin.on('data',d=>process.stdout.write(JSON.parse(d).id))")
ITEM8=$(api POST /v1/items '{"repo":"web","title":"Refactor auth guard","kind":"RISK","priority":"P1","owner":"agent"}' | node -e "process.stdin.on('data',d=>process.stdout.write(JSON.parse(d).id))")
ITEM9=$(api POST /v1/items '{"repo":"acme-shop","title":"Old duplicate task","kind":"BACKLOG","priority":"P3","owner":"agent"}' | node -e "process.stdin.on('data',d=>process.stdout.write(JSON.parse(d).id))")
ITEM10=$(api POST /v1/items '{"repo":"web","title":"Remove feature flag","kind":"BACKLOG","priority":"P3","owner":"human"}' | node -e "process.stdin.on('data',d=>process.stdout.write(JSON.parse(d).id))")

echo "== transitions + comments" >&2
api POST "/v1/items/$ITEM3/comments" '{"author":"orchestrator","text":"Waiting for human review."}' >/dev/null
api POST "/v1/items/$ITEM6/comments" '{"author":"agent","text":"Added a first draft of the limiter, needs load testing."}' >/dev/null
api POST "/v1/items/$ITEM9/drop" '{"why":"duplicate of ACME-1"}' >/dev/null
api POST "/v1/items/$ITEM10/done" '{"ref":"0000001"}' >/dev/null
api POST "/v1/items/$ITEM4/done" '{"ref":"0000002"}' >/dev/null

echo "== intake" >&2
api POST /v1/intake '{"text":"Add a dark mode toggle to settings, users keep asking for it.","channel":"web"}' >/dev/null
api POST /v1/intake '{"text":"Check why the importer crashes on large files.","channel":"web","repo_hint":"acme-shop"}' >/dev/null

echo "== decision" >&2
api POST /v1/decisions '{"repo":"acme-shop","title":"Payments go through a hosted provider, not a custom integration","why":"Less maintenance, faster start."}' >/dev/null

echo "== journal" >&2
api POST /v1/journal '{"repo":"acme-shop","type":"session.summary","text":"The seed session filled in the demo data."}' >/dev/null

echo "== more repos: api/mobile items so the sidebar has 4 repos with dots" >&2
ITEM11=$(api POST /v1/items '{"repo":"api","title":"Push notifications","kind":"UNVERIFIED","priority":"P1","owner":"agent"}' | node -e "process.stdin.on('data',d=>process.stdout.write(JSON.parse(d).id))")
ITEM12=$(api POST /v1/items '{"repo":"mobile","title":"Rotate partner API keys","kind":"BLOCKER","priority":"P0","owner":"human"}' | node -e "process.stdin.on('data',d=>process.stdout.write(JSON.parse(d).id))")

echo "== claim, intrude lease, inbox (for /r/:slug and /s/:session checks)" >&2
# Several distinct sessions across repos so the sidebar "live"
# indicator, the Sessions page, and session title fallbacks all have data —
# `title`/`title_source` are computed by the hub itself (not settable here),
# so untitled sessions just render their short id, which is expected.
SESSION_A="seed-session-aaaaaaaa"
SESSION_B="seed-session-bbbbbbbb"
SESSION_C="seed-session-cccccccc"
SESSION_D="seed-session-dddddddd"
api POST "/v1/items/$ITEM6/claim" "{\"session\":\"$SESSION_A\",\"paths\":[\"src/rate-limit.ts\"],\"intent\":\"add rate limiting\"}" >/dev/null
api POST /v1/intrude "{\"session\":\"$SESSION_B\",\"repo\":\"web\",\"paths\":[\"src/rate-limit.ts\"],\"intent\":\"urgent CI fix\",\"force\":true}" >/dev/null
api POST /v1/inbox "{\"to\":\"$SESSION_A\",\"from\":\"$SESSION_B\",\"repo\":\"web\",\"body\":\"Entering src/rate-limit.ts for a CI fix, see the intrude lease.\"}" >/dev/null
api POST "/v1/items/$ITEM11/claim" "{\"session\":\"$SESSION_C\",\"paths\":[\"app/push.ts\"],\"intent\":\"push token registration\"}" >/dev/null
api POST "/v1/items/$ITEM12/claim" "{\"session\":\"$SESSION_D\",\"paths\":[\"infra/keys.ts\"],\"intent\":\"partner key rotation\"}" >/dev/null
# NOTE: a true orphan file (session ended mid-edit) needs a real git checkout
# for the hub to read `git status` against — this virtual demo repo has no
# `path`, so it is left out here. Point `path` at a real scratch checkout and
# fire PostToolUse + SessionEnd hooks on it to see the orphan/adopt/override UI.

echo "" >&2
echo "== done ==" >&2
echo "hub running at $BASE (PID $HUB_PID), token in $LEDGER_DIR/.hub/token" >&2
echo "open:  LEDGER_DIR=$LEDGER_DIR LEDGER_HUB_URL=$BASE ledger open" >&2
echo "stop:  kill $HUB_PID" >&2

# Keep running in foreground so the caller can Ctrl-C when done looking.
wait "$HUB_PID"
