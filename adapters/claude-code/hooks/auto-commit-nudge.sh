#!/bin/bash
# Claude Code Stop hook (optional): periodic nudge to commit your own work.
#
# Plain `git status` counts every dirty file in a repo, so with two live
# sessions one agent gets told to commit the other's files — exactly what the
# ledger protocol forbids. This hook asks the hub instead (`GET /v1/nudge`):
#
#   * repos are not hard-coded: the hub derives them from the session (its home
#     repo plus the repos where the session has touched files),
#   * the threshold and the "late evening" rule count ONLY this session's own
#     files and files nobody owns; other live sessions' files are never counted
#     and never mentioned in the text,
#   * the message carries the concrete command
#     `git -C <repo> commit --only -- <my files>`,
#   * hub down or not answering -> exit 0 (fail-open, like every ledger hook),
#   * a cooldown stays in place: without it every following turn would block.
#
# The whole computation lives in the hub, so this script needs neither `jq` nor
# any knowledge of the ledger, and the "never foreign files" rule has a single
# tested home.
#
# Wire it by hand under `Stop` in ~/.claude/settings.json (it is NOT installed
# by install-hooks.mjs):
#   { "type": "command", "command": "/path/to/auto-commit-nudge.sh", "timeout": 5 }

set -u

PAYLOAD="$(cat)"          # hook JSON on stdin

THRESHOLD="${LEDGER_NUDGE_THRESHOLD:-20}"
COOLDOWN="${LEDGER_NUDGE_COOLDOWN:-2700}"     # 45 min
LEDGER="${LEDGER_DIR:-$HOME/.ledger}"
STATE_FILE="${LEDGER_NUDGE_STATE:-$LEDGER/.hub/nudge-state}"
PORT="${LEDGER_HUB_PORT:-4747}"
TOKEN_FILE="$LEDGER/.hub/token"

# Guard disabled -> no nudging (same kill switch as the other hooks).
[ "${LEDGER_HUB_GUARD:-on}" = "off" ] && exit 0

# Session id: from the environment (SessionStart writes it into
# CLAUDE_ENV_FILE), otherwise from the payload.
SESSION="${LEDGER_SESSION:-}"
if [ -z "$SESSION" ]; then
  SESSION="$(printf '%s' "$PAYLOAD" \
    | sed -n 's/.*"session_id"[[:space:]]*:[[:space:]]*"\([^"]\{1,128\}\)".*/\1/p' \
    | head -n1)"
fi
[ -z "$SESSION" ] && exit 0
# Only a safe character subset goes into the URL; real session ids have nothing else.
case "$SESSION" in
  *[!A-Za-z0-9._-]*) exit 0 ;;
esac

[ -r "$TOKEN_FILE" ] || exit 0
TOKEN="$(tr -d '\n' < "$TOKEN_FILE")"
[ -z "$TOKEN" ] && exit 0

HOUR="$(date +%H | sed 's/^0//')"
LATE=0
[ "$HOUR" -ge 22 ] 2>/dev/null && LATE=1

TEXT="$(curl -fsS --max-time 2 \
  -H "X-Hub-Token: $TOKEN" \
  "http://127.0.0.1:$PORT/v1/nudge?session=$SESSION&threshold=$THRESHOLD&late=$LATE" \
  2>/dev/null)" || exit 0        # hub down / 4xx -> fail-open

[ -z "${TEXT//[[:space:]]/}" ] && exit 0

NOW="$(date +%s)"
LAST=0
[ -f "$STATE_FILE" ] && LAST="$(cat "$STATE_FILE" 2>/dev/null)"
case "$LAST" in
  ''|*[!0-9]*) LAST=0 ;;
esac
if [ $((NOW - LAST)) -lt "$COOLDOWN" ]; then
  exit 0
fi
mkdir -p "$(dirname "$STATE_FILE")"
printf '%s\n' "$NOW" > "$STATE_FILE"

# `$TEXT` embeds real filenames from `git status` (the hub's `GET /v1/nudge`
# already narrows those to a safe display charset and fences them in a
# labelled block). Strip stray C0 control bytes here too, as defense in depth.
TEXT="$(printf '%s' "$TEXT" | tr -d '\000-\010\013\014\016-\037\177')"
printf '%s\n' "$TEXT" >&2
exit 2
