#!/usr/bin/env bash
# Agent Ledger installer. Idempotent; safe to re-run after `git pull`.
#
#   git clone <repo> agent-ledger && cd agent-ledger && ./install.sh
#
# What it does (nothing outside $HOME unless you pass --allow-brew; nothing
# Claude-specific by default):
#   1. pnpm install + build the web UI
#   2. creates the ledger directory (default ~/.ledger, git-initialised,
#      `.hub/` gitignored) and a verified copy of gitleaks inside it
#   3. writes the `ledger` shim to ~/.local/bin
#   4. installs and starts the hub as a user service
#        macOS  -> launchd agent   ~/Library/LaunchAgents/<label>.plist
#        Linux  -> systemd user unit ~/.config/systemd/user/<label>.service
#
# Options:
#   --no-service                 skip step 4 (start the hub yourself)
#   --skip-gitleaks              do not fetch/copy gitleaks (commits go without the second secret check)
#   --allow-brew                 if the verified gitleaks download fails and gitleaks is not in PATH,
#                                run `brew install gitleaks` (writes outside $HOME). Without this flag
#                                brew is only used after an interactive yes; non-interactive runs skip it.
#   --port <n>                   hub port (same as LEDGER_HUB_PORT, default 4747). If the port is taken by
#                                another process the installer asks (TTY) or fails with a clear message.
#   --headless                   let the hub spawn an agent CLI headlessly (intake triage, grooming,
#                                reply workers): sets LEDGER_HEADLESS=1 and LEDGER_CLAUDE_BIN
#   --trust-claude-group         Claude Code adapter, optional: accept an agent binary that lives in a
#                                group-writable directory (e.g. Homebrew's /opt/homebrew/bin).
#                                Pinned to the binary's realpath and the directory's gid. Implies --headless.
#   --render-plist-only <path>   test seam: render the launchd plist to <path> and exit
#   --render-unit-only <path>    test seam: render the systemd unit to <path> and exit
#   -h, --help
#
# Environment:
#   LEDGER_DIR            ledger directory (default ~/.ledger)
#   LEDGER_HUB_PORT       hub port (default 4747; `--port` wins)
#   SHIM_DIR              where the `ledger` shim goes (default ~/.local/bin)
#   AGENT_LEDGER_LABEL    service label (default io.agent-ledger.hub)
#   LEDGER_PUSH, LEDGER_INTRUDE, LEDGER_RECAP_GUARD, LEDGER_RECAP_TAGS, LEDGER_WEB_REPLIES,
#   LEDGER_AGENTS_DIR, LEDGER_GROOM_WEEKLY   optional-feature flags; when set during install
#                         they are written into the service environment.
#
# Uninstall: ./uninstall.sh
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LABEL="${AGENT_LEDGER_LABEL:-io.agent-ledger.hub}"
LEDGER="${LEDGER_DIR:-$HOME/.ledger}"
PORT="${LEDGER_HUB_PORT:-4747}"
SHIM_DIR="${SHIM_DIR:-$HOME/.local/bin}"
SHIM="$SHIM_DIR/ledger"
NODE="$(command -v node || true)"
OS="$(uname -s)"

PLIST_DIR="$HOME/Library/LaunchAgents"
PLIST="$PLIST_DIR/$LABEL.plist"
UNIT_DIR="${XDG_CONFIG_HOME:-$HOME/.config}/systemd/user"
UNIT="$UNIT_DIR/$LABEL.service"

die() {
  echo "install: $*" >&2
  exit 1
}

usage() {
  sed -n '2,/^set -euo pipefail/p' "${BASH_SOURCE[0]}" | sed '$d' | sed 's/^# \{0,1\}//'
}

# Seams: `--render-plist-only <out>` / `--render-unit-only <out>` render the
# service file and exit — no pnpm install, no ledger/shim provisioning, no
# launchctl/systemctl. They let a regression test exercise the escaping and the
# `ensure_chain` directory hardening without touching the real home or the
# service manager.
RENDER_PLIST_ONLY=0
RENDER_UNIT_ONLY=0
OUT_FILE=""
NO_SERVICE=0
SKIP_GITLEAKS=0
ALLOW_BREW=0
HEADLESS=0
# Conscious opt-in to an agent binary in a group-writable directory. Without
# this flag the hub keeps the headless features OFF instead of executing a
# binary it cannot vouch for.
TRUST_CLAUDE_GROUP=0
ARGS=()
while (( $# > 0 )); do
  case "$1" in
    --render-plist-only)
      RENDER_PLIST_ONLY=1
      OUT_FILE="${2:?usage: install.sh --render-plist-only <output-plist-path>}"
      shift 2
      ;;
    --render-unit-only)
      RENDER_UNIT_ONLY=1
      OUT_FILE="${2:?usage: install.sh --render-unit-only <output-unit-path>}"
      shift 2
      ;;
    --no-service)
      NO_SERVICE=1
      shift
      ;;
    --skip-gitleaks)
      SKIP_GITLEAKS=1
      shift
      ;;
    --allow-brew)
      ALLOW_BREW=1
      shift
      ;;
    --port)
      PORT="${2:?usage: install.sh --port <number>}"
      shift 2
      ;;
    --headless)
      HEADLESS=1
      shift
      ;;
    --trust-claude-group)
      TRUST_CLAUDE_GROUP=1
      HEADLESS=1
      shift
      ;;
    -h | --help)
      usage
      exit 0
      ;;
    *)
      ARGS+=("$1")
      shift
      ;;
  esac
done
if (( ${#ARGS[@]} > 0 )); then
  die "unknown argument ${ARGS[0]} (try --help)"
fi
RENDER_ONLY=0
if [[ "$RENDER_PLIST_ONLY" == "1" || "$RENDER_UNIT_ONLY" == "1" ]]; then
  RENDER_ONLY=1
fi

# The label becomes part of a file name and of launchctl/systemctl arguments.
if [[ ! "$LABEL" =~ ^[A-Za-z0-9._-]+$ ]]; then
  die "AGENT_LEDGER_LABEL may only contain letters, digits, '.', '_' and '-'"
fi

if [[ -z "$NODE" ]]; then
  die "node not found in PATH — install Node >= 22.18 (https://nodejs.org)"
fi
NODE_MAJOR="$("$NODE" -p 'process.versions.node.split(".")[0]')"
NODE_MINOR="$("$NODE" -p 'process.versions.node.split(".")[1]')"
if (( NODE_MAJOR < 22 || (NODE_MAJOR == 22 && NODE_MINOR < 18) )); then
  die "node $("$NODE" -v) is too old — type stripping needs >= 22.18"
fi

validate_port() {
  [[ "$1" =~ ^[0-9]+$ ]] && (( 10#$1 >= 1 && 10#$1 <= 65535 )) \
    || die "invalid port \"$1\" — use a number between 1 and 65535 (--port / LEDGER_HUB_PORT)"
}
validate_port "$PORT"
PORT="$((10#$PORT))"

# >>> hub-probe (test seam: install-hub-probe.test.ts extracts this block by marker)
# Asks whatever answers on 127.0.0.1:$PORT who it is. `/v1/healthz` returns
# `{ok}` only to an unauthenticated caller; with THIS ledger's token it also
# returns `ledger` (the hub's ledger directory). A foreign process, or another
# hub with a different ledger directory, therefore never matches.
#   exit 0  = this ledger's hub        exit 10 = nothing listening (connection refused)
#   exit 11 = something else answers (other hub, other ledger, not HTTP, no `ledger` field)
probe_hub() {
  LEDGER_PROBE_PORT="$PORT" LEDGER_PROBE_DIR="$LEDGER" "$NODE" -e '
    const fs = require("node:fs");
    const dir = process.env.LEDGER_PROBE_DIR;
    const real = (p) => { try { return fs.realpathSync(p); } catch { return p; } };
    let token = "";
    try { token = fs.readFileSync(dir + "/.hub/token", "utf8").trim(); } catch {}
    fetch("http://127.0.0.1:" + process.env.LEDGER_PROBE_PORT + "/v1/healthz", {
      headers: token ? { "x-hub-token": token } : {},
      redirect: "manual",
      signal: AbortSignal.timeout(2000),
    }).then(async (res) => {
      let body = null;
      try { body = await res.json(); } catch {}
      const mine = body !== null && typeof body === "object" && typeof body.ledger === "string" &&
        real(body.ledger) === real(dir);
      process.exit(mine ? 0 : 11);
    }, (err) => process.exit(err && err.cause && err.cause.code === "ECONNREFUSED" ? 10 : 11));
  '
}

# Before installing a service: the port must be free, or already ours (re-install).
# Never a silent skip — a hub that "starts" on a port someone else owns would be
# reported as success while every `ledger` command talks to the stranger.
ensure_port_available() {
  local code answer
  while true; do
    code=0
    probe_hub || code=$?
    case "$code" in
      10) return 0 ;;
      0)
        echo "==> port $PORT: served by this ledger's hub already (re-install)"
        return 0
        ;;
    esac
    echo "install: port $PORT is in use by another process (not this ledger's hub)." >&2
    if [[ -t 0 && -t 1 ]]; then
      answer=""
      read -r -p "Another port for the hub (empty = abort): " answer || answer=""
      [[ -n "$answer" ]] || die "aborted — free port $PORT or re-run with --port <n> / LEDGER_HUB_PORT=<n>"
      validate_port "$answer"
      PORT="$((10#$answer))"
    else
      die "port $PORT is taken — free it, or re-run with --port <n> (or LEDGER_HUB_PORT=<n>)"
    fi
  done
}

# Waits until THIS ledger's hub answers on $PORT, then prints `ledger status`.
# A different process on the port is a failure, never a success.
wait_for_hub() {
  local code=0 foreign=0 _
  # Migrations at boot can delay the hub for more than a second, and
  # `ledger status` run before the hub opens its port reports "not running"
  # even though the service started. Poll up to 30 s.
  for _ in $(seq 1 60); do
    code=0
    probe_hub || code=$?
    if [[ "$code" == "0" ]]; then
      break
    elif [[ "$code" == "11" ]]; then
      # Our hub may still be starting with the old process answering; a stranger
      # stays a stranger, so give up after a few consecutive foreign answers.
      foreign=$((foreign + 1))
      (( foreign >= 4 )) && break
    else
      foreign=0
    fi
    sleep 0.5
  done
  if [[ "$code" == "11" ]]; then
    echo "install: something else answers on 127.0.0.1:$PORT — it is not the hub of $LEDGER. Free the port or use --port <n>." >&2
    return 1
  fi
  if [[ "$code" != "0" ]]; then
    echo "install: hub did not answer on 127.0.0.1:$PORT within 30 s — see $LEDGER/.hub/hub.log" >&2
    return 1
  fi
  LEDGER_DIR="$LEDGER" LEDGER_HUB_PORT="$PORT" LEDGER_HUB_URL="" "$SHIM" status || {
    echo "install: hub is not answering yet — see $LEDGER/.hub/hub.log" >&2
    return 1
  }
}

# gitleaks via Homebrew writes outside $HOME, so it needs consent: --allow-brew
# or an interactive yes. Non-interactive without the flag: skipped, with a note.
brew_gitleaks_if_allowed() {
  command -v gitleaks >/dev/null 2>&1 && return 0
  command -v brew >/dev/null 2>&1 || return 0
  local a=""
  if [[ "$ALLOW_BREW" == "1" ]]; then
    echo "==> gitleaks missing — installing via brew (--allow-brew)"
    brew install gitleaks || echo "    note: brew install gitleaks failed"
  elif [[ -t 0 && -t 1 ]]; then
    read -r -p "gitleaks is missing. Install it with Homebrew (writes outside \$HOME)? [y/N] " a || a=""
    case "$a" in
      y | Y | yes | YES)
        brew install gitleaks || echo "    note: brew install gitleaks failed"
        ;;
      *) echo "    note: brew install skipped" ;;
    esac
  else
    echo "    note: gitleaks is missing; brew is available but not used without consent."
    echo "          Re-run with --allow-brew, or install gitleaks yourself."
  fi
  return 0
}
# <<< hub-probe

# ---------------------------------------------------------------------------
# Escaping. Values embedded in the service file (paths, port, the agent
# binary) come from env vars the caller of this script controls; an unescaped
# `&`/`<`/`"` could break out of a plist `<string>` element and inject
# arbitrary plist XML (e.g. a second `ProgramArguments`), and a newline could
# inject a second directive into a systemd unit.
# ---------------------------------------------------------------------------
xml_escape() {
  # bash >= 5.2 (`patsub_replacement`, on by default) treats an unquoted `&` in a
  # `${s//pat/repl}` replacement as "the matched text", so `&lt;` would render
  # as `<lt;` and the escaping would silently stop working (plist injection).
  # macOS ships bash 3.2, where the option does not exist.
  shopt -u patsub_replacement 2>/dev/null || true
  local s="$1"
  s="${s//&/&amp;}"
  s="${s//</&lt;}"
  s="${s//>/&gt;}"
  s="${s//\"/&quot;}"
  s="${s//\'/&apos;}"
  printf '%s' "$s"
}

# systemd: a value must stay on one line, and `%` (specifiers) must be doubled.
assert_one_line() {
  case "$1" in
    *$'\n'* | *$'\r'*) die "refusing a value with a line break in a systemd unit: ${1//[$'\r\n']/ }" ;;
  esac
}
# Inside a double-quoted systemd word: backslash, quote and `%`.
sd_quote_escape() {
  local s="$1"
  assert_one_line "$s"
  s="${s//\\/\\\\}"
  s="${s//\"/\\\"}"
  s="${s//%/%%}"
  printf '%s' "$s"
}
# ExecStart= additionally expands `$VAR`.
sd_exec_escape() {
  local s
  s="$(sd_quote_escape "$1")"
  s="${s//\$/\$\$}"
  printf '%s' "$s"
}
# Unquoted path (StandardOutput=append:<path>): only `%` is special.
sd_path_escape() {
  local s="$1"
  assert_one_line "$s"
  s="${s//%/%%}"
  printf '%s' "$s"
}

# ---------------------------------------------------------------------------
# Extra service environment: feature flags passed through from the installer's
# own environment, plus the headless settings. Raw names/values are collected
# here and escaped at render time for the target format.
# ---------------------------------------------------------------------------
EXTRA_NAMES=()
EXTRA_VALUES=()
add_extra() {
  EXTRA_NAMES+=("$1")
  EXTRA_VALUES+=("$2")
}

PASSTHROUGH_VARS="LEDGER_PUSH LEDGER_INTRUDE LEDGER_RECAP_GUARD LEDGER_RECAP_TAGS LEDGER_WEB_REPLIES LEDGER_AGENTS_DIR LEDGER_GROOM_WEEKLY"
for v in $PASSTHROUGH_VARS; do
  if [[ -n "${!v:-}" ]]; then
    add_extra "$v" "${!v}"
  fi
done

# Headless features (opt-in): the hub spawns an agent CLI, and a service
# manager has no useful PATH, so the binary path must be absolute and resolved
# now. If the CLI is not installed, the feature stays off and the install does
# not fail.
if [[ "$HEADLESS" == "1" ]]; then
  CLAUDE_BIN="${LEDGER_CLAUDE_BIN:-$(command -v claude || true)}"
  CLAUDE_FOUND=0
  if [[ -n "$CLAUDE_BIN" && -x "$CLAUDE_BIN" ]]; then
    case "$CLAUDE_BIN" in
      /*)
        CLAUDE_FOUND=1
        add_extra LEDGER_HEADLESS 1
        add_extra LEDGER_CLAUDE_BIN "$CLAUDE_BIN"
        echo "==> agent CLI $CLAUDE_BIN (headless features on)"
        ;;
      *) echo "    note: the agent CLI path is not absolute ($CLAUDE_BIN) — headless features left off" ;;
    esac
  else
    echo "    note: agent CLI not found — headless features stay off (set LEDGER_CLAUDE_BIN and re-run)"
  fi

  # The hub refuses to spawn the agent CLI from a group-writable directory.
  # The flag records that the machine's owner accepted that risk; the hub also
  # writes it into the ledger journal at boot, so the decision is auditable and
  # not just a line in a service file.
  #
  # The flag is pinned to WHAT the installer saw — the realpath of the binary
  # and the gid of the group-writable directory in its chain. The hub honours
  # the opt-in only while both values still match, so the approval does not
  # silently follow the binary to a new location, or survive a `chgrp` of its
  # directory to a group with completely different membership.
  if [[ "$TRUST_CLAUDE_GROUP" == "1" ]]; then
    if [[ "$CLAUDE_FOUND" == "1" ]]; then
      # One node pass: resolve the realpath and walk its directory chain for the
      # first group-writable component, reporting that component's gid. `g+w` is
      # the only condition the flag may excuse; world-writable and foreign owners
      # are refused by the hub no matter what this records.
      CLAUDE_PIN="$("$NODE" -e '
        const fs = require("node:fs");
        const path = require("node:path");
        try {
          const real = fs.realpathSync(process.argv[1]);
          let dir = path.dirname(real);
          let gid = null;
          for (;;) {
            const st = fs.lstatSync(dir);
            if ((st.mode & 0o020) !== 0 && (st.mode & 0o002) === 0) { gid = st.gid; break; }
            const parent = path.dirname(dir);
            if (parent === dir) break;
            dir = parent;
          }
          if (gid === null) { process.stdout.write(`none\t${real}`); }
          else { process.stdout.write(`${gid}\t${real}`); }
        } catch {
          process.stdout.write("");
        }
      ' "$CLAUDE_BIN" 2>/dev/null || true)"
      CLAUDE_PIN_GID="${CLAUDE_PIN%%$'\t'*}"
      CLAUDE_PIN_REAL="${CLAUDE_PIN#*$'\t'}"
      if [[ -z "$CLAUDE_PIN" || "$CLAUDE_PIN_GID" == "none" || -z "$CLAUDE_PIN_REAL" ]]; then
        # Nothing group-writable in the chain -> the hub trusts the binary without
        # any opt-in, so recording one would only widen the trust for later.
        echo "    note: --trust-claude-group is not needed — no group-writable directory in the"
        echo "          path to the agent CLI. Nothing is pinned."
      else
        add_extra LEDGER_TRUST_CLAUDE_GROUP 1
        add_extra LEDGER_TRUST_CLAUDE_GID "$CLAUDE_PIN_GID"
        add_extra LEDGER_TRUST_CLAUDE_REALPATH "$CLAUDE_PIN_REAL"
        echo "    note: --trust-claude-group — allowing the agent CLI in a group-writable directory,"
        echo "          pinned to gid $CLAUDE_PIN_GID and path $CLAUDE_PIN_REAL."
        echo "          Knowingly accepted risk: any account in that group can swap the binary the"
        echo "          hub runs. A different group or a different path turns headless off with a"
        echo "          message. The decision is written to the ledger journal."
      fi
    else
      echo "    note: --trust-claude-group ignored — no agent CLI configured"
    fi
  fi
fi

# S11 / R1: refuse to mkdir/chmod through a symlink, refuse a directory we
# don't own, and refuse one that is group/other-writable — any of the three
# would let another local user redirect the ledger (and its token) or the shim
# onto a path they control.
dir_mode() {
  if [[ "$OS" == "Darwin" ]]; then
    stat -f '%OLp' "$1" 2>/dev/null || echo 777
  else
    stat -c '%a' "$1" 2>/dev/null || echo 777
  fi
}

assert_safe_dir() {
  local d="$1"
  if [[ -L "$d" ]]; then
    die "$d is a symlink, refusing"
  fi
  if [[ -e "$d" ]]; then
    if [[ ! -O "$d" ]]; then
      die "$d is not owned by this user, refusing"
    fi
    if [[ ! -d "$d" ]]; then
      die "$d is not a directory, refusing"
    fi
    local perms
    perms="$(dir_mode "$d")"
    # Group- or other-writable -> someone else can rename/replace children.
    if (( (8#$perms & 8#022) != 0 )); then
      die "$d is group/other-writable ($perms), refusing"
    fi
  fi
}

# Checking only the final directory is not enough. `$LEDGER` and `$SHIM_DIR` are
# multi-component paths under `$HOME`; if an intermediate component
# (`~/.local`, `~/.config`) is a symlink or is world-writable, the final
# component is attacker-controlled no matter how it looks itself. So the whole
# chain from `$HOME` down is validated, one component at a time, and `mkdir`
# happens per component so nothing is ever created *through* an unvalidated
# link.
ensure_chain() {
  local target="$1" mode="${2:-700}"
  case "$target" in
    "$HOME" | "$HOME"/*) ;;
    *) die "$target is not under \$HOME — refusing (set LEDGER_DIR/SHIM_DIR under \$HOME)" ;;
  esac
  assert_safe_dir "$HOME"
  [[ "$target" == "$HOME" ]] && return 0
  local rest="${target#"$HOME"/}" current="$HOME" part
  local IFS=/
  for part in $rest; do
    [[ -z "$part" || "$part" == "." ]] && continue
    if [[ "$part" == ".." ]]; then
      die "$target contains '..' — refusing"
    fi
    current="$current/$part"
    assert_safe_dir "$current"
    if [[ ! -e "$current" ]]; then
      mkdir -m "$mode" "$current"
      assert_safe_dir "$current"
    fi
  done
}

# Shared template substitution. The caller exports the *_X variables (already
# escaped for the target format) and EXTRA_ENV (a pre-rendered block). One
# pass, literal replacement: no regex/`gsub` replacement semantics (where `&`
# and `\` are special and differ between awk implementations), no `sed` with a
# delimiter that a value can contain, and a value that happens to contain
# `@PORT@` is never substituted a second time.
subst_template() {
  local tmpl="$1" out="$2"
  awk '
    BEGIN {
      n = split("@LABEL@ @NODE@ @HUB@ @LEDGER@ @PORT@ @LOG@", names, " ")
      split("LABEL_X NODE_X HUB_X LEDGER_X PORT_X LOG_X", vars, " ")
      for (k = 1; k <= n; k++) val[names[k]] = ENVIRON[vars[k]]
    }
    function render(line,   out, i, k, hit) {
      out = ""
      while ((i = index(line, "@")) > 0) {
        out = out substr(line, 1, i - 1)
        line = substr(line, i)
        hit = 0
        for (k = 1; k <= n; k++) {
          if (substr(line, 1, length(names[k])) == names[k]) {
            out = out val[names[k]]
            line = substr(line, length(names[k]) + 1)
            hit = 1
            break
          }
        }
        if (!hit) { out = out "@"; line = substr(line, 2) }
      }
      return out line
    }
    index($0, "@EXTRA_ENV@") { printf "%s", ENVIRON["EXTRA_ENV"]; next }
    { print render($0) }
  ' "$tmpl" > "$out.tmp"
  mv "$out.tmp" "$out"
}

# The service directory gets the same `ensure_chain` hardening as the
# ledger/shim dirs before anything is written into it. Defined here (not
# guarded by RENDER_ONLY below) since the render seams call it too.
render_plist() {
  local tmpl="$1" out="$2" i extra=""
  ensure_chain "$(dirname "$out")" 755
  for ((i = 0; i < ${#EXTRA_NAMES[@]}; i++)); do
    extra="$extra    <key>${EXTRA_NAMES[$i]}</key>
    <string>$(xml_escape "${EXTRA_VALUES[$i]}")</string>
"
  done
  LABEL_X="$(xml_escape "$LABEL")" \
  NODE_X="$(xml_escape "$NODE")" \
  HUB_X="$(xml_escape "$REPO/packages/hub/src/bin.ts")" \
  LEDGER_X="$(xml_escape "$LEDGER")" \
  PORT_X="$(xml_escape "$PORT")" \
  LOG_X="$(xml_escape "$LEDGER/.hub/hub.log")" \
  EXTRA_ENV="$extra" \
  subst_template "$tmpl" "$out"
}

render_unit() {
  local tmpl="$1" out="$2" i extra=""
  ensure_chain "$(dirname "$out")" 755
  # Checked here, in the main shell: a `die` inside the `$( )` escape helpers
  # below would only end that subshell and the render would carry on.
  assert_one_line "$NODE"
  assert_one_line "$REPO"
  assert_one_line "$LEDGER"
  assert_one_line "$PORT"
  for ((i = 0; i < ${#EXTRA_VALUES[@]}; i++)); do
    assert_one_line "${EXTRA_VALUES[$i]}"
  done
  for ((i = 0; i < ${#EXTRA_NAMES[@]}; i++)); do
    extra="${extra}Environment=\"${EXTRA_NAMES[$i]}=$(sd_quote_escape "${EXTRA_VALUES[$i]}")\"
"
  done
  LABEL_X="$LABEL" \
  NODE_X="$(sd_exec_escape "$NODE")" \
  HUB_X="$(sd_exec_escape "$REPO/packages/hub/src/bin.ts")" \
  LEDGER_X="$(sd_quote_escape "$LEDGER")" \
  PORT_X="$(sd_quote_escape "$PORT")" \
  LOG_X="$(sd_path_escape "$LEDGER/.hub/hub.log")" \
  EXTRA_ENV="$extra" \
  subst_template "$tmpl" "$out"
}

if [[ "$RENDER_PLIST_ONLY" == "1" ]]; then
  echo "==> plist $OUT_FILE"
  render_plist "$REPO/ops/launchd/agent-ledger.plist.tmpl" "$OUT_FILE"
  exit 0
fi
if [[ "$RENDER_UNIT_ONLY" == "1" ]]; then
  echo "==> systemd unit $OUT_FILE"
  render_unit "$REPO/ops/systemd/agent-ledger.service.tmpl" "$OUT_FILE"
  exit 0
fi

# ---------------------------------------------------------------------------
# Real install
# ---------------------------------------------------------------------------
command -v git >/dev/null 2>&1 || die "git not found in PATH — the ledger is a git repository"
command -v pnpm >/dev/null 2>&1 || die "pnpm not found in PATH — install it (e.g. \`corepack enable\`)"

if [[ "$NO_SERVICE" != "1" ]]; then
  ensure_port_available
fi

echo "==> pnpm install"
( cd "$REPO" && pnpm install --frozen-lockfile )

# `packages/web/dist` is not committed — the hub serves a placeholder page
# without it (harmless), but that means a broken web build would silently ship
# a hub with no UI instead of failing the install. Build it now, before the
# service starts, and fail the install if it fails.
if [[ -d "$REPO/packages/web" ]]; then
  echo "==> pnpm --filter @agent-ledger/web build"
  ( cd "$REPO" && pnpm --filter @agent-ledger/web build )
fi

echo "==> ledger $LEDGER"
ensure_chain "$LEDGER" 700
ensure_chain "$LEDGER/.hub" 700
chmod 700 "$LEDGER" "$LEDGER/.hub"

# The ledger is a git repository. The hub would create it at first boot, but
# doing it here makes the first `ledger` command work offline of the service
# and keeps `.hub/` (token, log, managed binaries) out of every commit.
if ! git -C "$LEDGER" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  git -C "$LEDGER" init -q
  git -C "$LEDGER" symbolic-ref HEAD refs/heads/main
  echo "    git repo initialised (main)"
fi
GITIGNORE_FILE="$LEDGER/.gitignore"
for line in '.hub/' '*.tmp'; do
  if ! grep -qxF "$line" "$GITIGNORE_FILE" 2>/dev/null; then
    printf '%s\n' "$line" >> "$GITIGNORE_FILE"
  fi
done
chmod 600 "$GITIGNORE_FILE"

# gitleaks is the second line of defence in front of every ledger commit (the
# hub's own secret scanner is the first). Best-effort: a machine without
# network just gets a warning — a failed fetch must not stop the hub from being
# installed.
#
# The hub does not execute gitleaks from wherever it happens to live
# (`/opt/homebrew/bin`, `/usr/local/bin` can be writable by other admin
# accounts, which could swap the scanner for a no-op). Instead the binary is
# COPIED into `$LEDGER/.hub/bin/gitleaks` (directory chain validated from
# `$HOME` and 0700, file 0500, owner = this user) and its sha256 is recorded
# next to it. The hub verifies owner, mode, directory chain and digest before
# every spawn and runs nothing else. After upgrading gitleaks the copy no
# longer matches — just run `./install.sh` again.
#
# The preferred source is the official GitHub release: download
# `gitleaks_<ver>_<os>_<arch>.tar.gz` AND `gitleaks_<ver>_checksums.txt` over
# HTTPS, verify the tarball against the checksums line for exactly that asset,
# and take the binary out of the verified tarball. The version is PINNED here
# (not "latest"), so an upgrade is a reviewable change to this file rather than
# whatever upstream published this morning.
#
# Residual TOFU — deliberately not solved here: the checksums file is fetched
# over the same channel as the tarball and is NOT signed, so this proves
# "tarball matches the checksums GitHub served us", not "upstream authored it".
# A GitHub compromise (or a TLS-terminating proxy trusted by this machine)
# defeats it. Closing that needs the cosign/SLSA attestation for the release.
# What it DOES close is the local half of the problem — the scanner no longer
# comes from a directory any admin account on the machine can write.
GITLEAKS_VERSION="${GITLEAKS_VERSION:-8.30.1}"
GITLEAKS_BASE_URL="${GITLEAKS_BASE_URL:-https://github.com/gitleaks/gitleaks/releases/download}"

sha256_of() {
  if command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$1" | awk '{print $1}'
  else
    sha256sum "$1" | awk '{print $1}'
  fi
}

# Map `uname` onto the release asset's os/arch tokens. An unknown pair is not
# guessed — it falls back to a PATH copy with the warning.
gitleaks_asset_platform() {
  local os arch
  case "$OS" in
    Darwin) os=darwin ;;
    Linux) os=linux ;;
    *) return 1 ;;
  esac
  case "$(uname -m)" in
    arm64 | aarch64) arch=arm64 ;;
    x86_64 | amd64) arch=x64 ;;
    *) return 1 ;;
  esac
  printf '%s_%s' "$os" "$arch"
}

# Echoes the path to a verified `gitleaks` binary in a 0700 temp dir, or fails.
# Everything (including the failure path) is quiet except the echoed path, so
# the caller can capture it with `$( )`.
gitleaks_fetch_verified() {
  local platform tarball url_tar url_sums tmp expected actual
  platform="$(gitleaks_asset_platform)" || return 1
  tarball="gitleaks_${GITLEAKS_VERSION}_${platform}.tar.gz"
  url_tar="$GITLEAKS_BASE_URL/v$GITLEAKS_VERSION/$tarball"
  url_sums="$GITLEAKS_BASE_URL/v$GITLEAKS_VERSION/gitleaks_${GITLEAKS_VERSION}_checksums.txt"
  tmp="$(mktemp -d "${TMPDIR:-/tmp}/agent-ledger-gitleaks.XXXXXX")" || return 1
  chmod 700 "$tmp"
  # `--proto '=https'` refuses a plaintext redirect; `-f` makes a 404 (a version
  # that does not exist) a failure instead of saving an HTML error page.
  if ! curl --proto '=https' --tlsv1.2 -fsSL --max-time 120 \
    -o "$tmp/$tarball" "$url_tar" 2>/dev/null; then
    rm -rf "$tmp"
    return 1
  fi
  if ! curl --proto '=https' --tlsv1.2 -fsSL --max-time 60 \
    -o "$tmp/checksums.txt" "$url_sums" 2>/dev/null; then
    rm -rf "$tmp"
    return 1
  fi
  # Anchored on the exact asset name: a checksums file listing many assets must
  # not let the line for a DIFFERENT platform satisfy this check.
  expected="$(awk -v want="$tarball" '$2 == want || $2 == "*" want { print $1; exit }' \
    "$tmp/checksums.txt")"
  if [[ ! "$expected" =~ ^[0-9a-f]{64}$ ]]; then
    rm -rf "$tmp"
    return 1
  fi
  actual="$(sha256_of "$tmp/$tarball")"
  if [[ "$actual" != "$expected" ]]; then
    echo "install: sha256 of $tarball does NOT match the official checksums — discarding" >&2
    rm -rf "$tmp"
    return 1
  fi
  # Only now is the archive touched. `-C` keeps the extraction inside the temp
  # dir even if the archive carries absolute or `..` paths.
  if ! tar -xzf "$tmp/$tarball" -C "$tmp" gitleaks 2>/dev/null; then
    rm -rf "$tmp"
    return 1
  fi
  if [[ ! -f "$tmp/gitleaks" ]]; then
    rm -rf "$tmp"
    return 1
  fi
  chmod 500 "$tmp/gitleaks"
  printf '%s' "$tmp/gitleaks"
}

GITLEAKS_REAL=""
GITLEAKS_ORIGIN=""
GITLEAKS_TMPDIR=""
if [[ "$SKIP_GITLEAKS" == "1" ]]; then
  echo "==> gitleaks: skipped (--skip-gitleaks)"
else
  echo "==> gitleaks: verifying the official release v$GITLEAKS_VERSION"
  if GITLEAKS_REAL="$(gitleaks_fetch_verified)" && [[ -n "$GITLEAKS_REAL" ]]; then
    GITLEAKS_TMPDIR="$(dirname "$GITLEAKS_REAL")"
    GITLEAKS_ORIGIN="upstream v$GITLEAKS_VERSION (sha256 verified against gitleaks_${GITLEAKS_VERSION}_checksums.txt)"
    echo "    sha256 matches the official checksums"
  else
    GITLEAKS_REAL=""
    echo "    note: could not download/verify the official release (network, version, platform)."
    brew_gitleaks_if_allowed
    GITLEAKS_SRC="$(command -v gitleaks || true)"
    if [[ -n "$GITLEAKS_SRC" ]]; then
      # realpath: Homebrew's `bin/gitleaks` is a symlink into the Cellar, and the
      # copy must come from the file that actually gets executed.
      GITLEAKS_REAL="$("$NODE" -p 'require("node:fs").realpathSync(process.argv[1])' "$GITLEAKS_SRC" 2>/dev/null || echo "$GITLEAKS_SRC")"
      GITLEAKS_ORIGIN="PATH ($GITLEAKS_SRC) — UNVERIFIED upstream"
      echo "    note: taking a copy of $GITLEAKS_SRC — UNVERIFIED upstream (TOFU)."
      echo "          When the network is back, run ./install.sh again and the copy gets verified."
    fi
  fi

  if [[ -n "$GITLEAKS_REAL" ]]; then
    ensure_chain "$LEDGER/.hub/bin" 700
    chmod 700 "$LEDGER/.hub/bin"
    GITLEAKS_DST="$LEDGER/.hub/bin/gitleaks"
    if [[ ! -f "$GITLEAKS_REAL" ]]; then
      echo "    note: $GITLEAKS_REAL is not a file — no copy was made for the hub"
    else
      rm -f "$GITLEAKS_DST" "$GITLEAKS_DST.tmp" "$GITLEAKS_DST.sha256" "$GITLEAKS_DST.sha256.tmp" \
        "$GITLEAKS_DST.origin" "$GITLEAKS_DST.origin.tmp"
      cp "$GITLEAKS_REAL" "$GITLEAKS_DST.tmp"
      chmod 500 "$GITLEAKS_DST.tmp"
      mv "$GITLEAKS_DST.tmp" "$GITLEAKS_DST"
      # Digest of the copy we just placed (not of the source), so the recorded
      # value always describes the bytes the hub will execute.
      GITLEAKS_SHA="$(sha256_of "$GITLEAKS_DST")"
      printf '%s\n' "$GITLEAKS_SHA" > "$GITLEAKS_DST.sha256.tmp"
      chmod 400 "$GITLEAKS_DST.sha256.tmp"
      mv "$GITLEAKS_DST.sha256.tmp" "$GITLEAKS_DST.sha256"
      # Provenance next to the digest, so "where did this binary come from" is
      # answerable later without re-running the install.
      printf '%s\n' "$GITLEAKS_ORIGIN" > "$GITLEAKS_DST.origin.tmp"
      chmod 400 "$GITLEAKS_DST.origin.tmp"
      mv "$GITLEAKS_DST.origin.tmp" "$GITLEAKS_DST.origin"
      echo "==> gitleaks $("$GITLEAKS_DST" version 2>/dev/null | head -1) -> $GITLEAKS_DST (sha256 ${GITLEAKS_SHA:0:12}…)"
      echo "    source: $GITLEAKS_ORIGIN"
      echo "    note: the hub runs ONLY this copy — after a version change run ./install.sh again."
    fi
  else
    echo "    note: could not obtain gitleaks — the hub commits the ledger without a second check."
    echo "          Install it by hand (https://github.com/gitleaks/gitleaks) and run ./install.sh again"
  fi
fi
# `set -e`: a bare `[[ … ]] && cmd` that tests false returns 1 and would abort
# the install right here, so this is a plain `if`.
if [[ -n "$GITLEAKS_TMPDIR" ]]; then
  rm -rf "$GITLEAKS_TMPDIR"
  GITLEAKS_TMPDIR=""
fi

echo "==> shim $SHIM"
ensure_chain "$SHIM_DIR" 755
# Precompile the hook fast path. Node's on-the-fly type stripping costs ~17 ms
# of the ~67 ms p95 hook budget; stripping ahead of time with the tsc we
# already depend on brings p95 to ~46 ms. Optional by design — if this fails,
# the shim below still runs the `.ts` sources.
if ( cd "$REPO" && "$NODE" scripts/build-hook.mjs ); then
  echo "==> hook fast path compiled"
else
  echo "    note: build-hook.mjs failed — hooks will run from .ts (slower, still works)"
fi

# The freshness check has to cover EVERY source of the hook entry, not just a
# few of them: editing one source while a stale `dist/hook/bin.js` keeps
# winning would silently run the old behaviour. Enumerated at install time (the
# shim must not glob at every invocation; that would cost more than the build
# it protects).
HOOK_SRCS=""
HOOK_SRC_COUNT=0
for f in "$REPO"/packages/cli/src/hook*.ts "$REPO"/packages/cli/src/bin.ts; do
  [ -f "$f" ] || continue
  # Tests are not sources of the bundle — a test edit must not invalidate it.
  case "$f" in *.test.ts) continue ;; esac
  HOOK_SRC_COUNT=$((HOOK_SRC_COUNT + 1))
  # `$f` (and `$REPO`/`$NODE` below) land verbatim in a script this heredoc
  # WRITES — a repo checked out under a path containing `"` or `$` would
  # otherwise break out of the generated shim's own quoting (or, with `$(...)`,
  # inject a command that runs on every `ledger` invocation). `printf %q`
  # shell-quotes the value once here, at generation time, so the shim always
  # sees one safe token no matter what the path contains.
  HOOK_SRCS="$HOOK_SRCS \\
  && [ \"\$HOOK_JS\" -nt $(printf '%q' "$f") ]"
done

if [ "$HOOK_SRC_COUNT" -eq 0 ]; then
  # The glob matched nothing — the layout changed in a way this script does not
  # understand, so it cannot prove `dist/hook/bin.js` is fresh. Trusting it
  # anyway (no sources -> no checks -> the `if` always wins) would silently run
  # a build that could be arbitrarily stale. Go straight to the `.ts` sources.
  echo "    note: no hook source found (hook*.ts/bin.ts) — the shim runs .ts directly, no dist fast path"
  cat > "$SHIM.tmp" <<EOF
#!/usr/bin/env bash
# agent-ledger shim (generated by install.sh)
exec $(printf '%q' "$NODE") $(printf '%q' "$REPO/packages/cli/src/bin.ts") "\$@"
EOF
else
  cat > "$SHIM.tmp" <<EOF
#!/usr/bin/env bash
# agent-ledger shim (generated by install.sh)
# Use the precompiled hook entry, but only while it is newer than ALL of its
# sources. A stale build must never win over the truth in src/.
HOOK_JS=$(printf '%q' "$REPO/packages/cli/dist/hook/bin.js")
if [ "\$1" = "hook" ] \\
  && [ -f "\$HOOK_JS" ]$HOOK_SRCS; then
  exec $(printf '%q' "$NODE") "\$HOOK_JS" "\$@"
fi
exec $(printf '%q' "$NODE") $(printf '%q' "$REPO/packages/cli/src/bin.ts") "\$@"
EOF
fi
chmod 755 "$SHIM.tmp"
mv "$SHIM.tmp" "$SHIM"
case ":$PATH:" in
  *":$SHIM_DIR:"*) ;;
  *) echo "    note: $SHIM_DIR is not in PATH — add it to your shell profile" ;;
esac

# ---------------------------------------------------------------------------
# Service
# ---------------------------------------------------------------------------
install_launchd() {
  echo "==> launchd agent $PLIST"
  render_plist "$REPO/ops/launchd/agent-ledger.plist.tmpl" "$PLIST"
  echo "==> launchctl bootstrap gui/$UID"
  launchctl bootout "gui/$UID/$LABEL" 2>/dev/null || true
  # bootout is asynchronous — bootstrapping while the old job is still being torn
  # down fails with "Bootstrap failed: 5: Input/output error".
  local _
  for _ in $(seq 1 50); do
    launchctl print "gui/$UID/$LABEL" >/dev/null 2>&1 || break
    sleep 0.2
  done
  if ! launchctl bootstrap "gui/$UID" "$PLIST"; then
    sleep 2
    launchctl bootstrap "gui/$UID" "$PLIST"
  fi
  launchctl kickstart -k "gui/$UID/$LABEL"
}

install_systemd() {
  echo "==> systemd user unit $UNIT"
  render_unit "$REPO/ops/systemd/agent-ledger.service.tmpl" "$UNIT"
  chmod 644 "$UNIT"
  systemctl --user daemon-reload
  systemctl --user enable "$LABEL.service"
  systemctl --user restart "$LABEL.service"
  if command -v loginctl >/dev/null 2>&1; then
    echo "    note: the unit runs while you are logged in. To keep it running after logout:"
    echo "          loginctl enable-linger \"\$USER\""
  fi
}

manual_start_hint() {
  cat <<EOF
==> start the hub yourself (no service installed):
    LEDGER_DIR=$(printf '%q' "$LEDGER") LEDGER_HUB_PORT=$PORT \\
      $(printf '%q' "$NODE") --disable-warning=ExperimentalWarning $(printf '%q' "$REPO/packages/hub/src/bin.ts")
EOF
}

SERVICE_STARTED=0
if [[ "$NO_SERVICE" == "1" ]]; then
  echo "==> service: skipped (--no-service)"
  manual_start_hint
else
  case "$OS" in
    Darwin)
      install_launchd
      SERVICE_STARTED=1
      ;;
    Linux)
      if command -v systemctl >/dev/null 2>&1 && systemctl --user show-environment >/dev/null 2>&1; then
        install_systemd
        SERVICE_STARTED=1
      else
        echo "    note: no systemd user session available — service not installed"
        manual_start_hint
      fi
      ;;
    *)
      echo "    note: no service support for $OS — service not installed"
      manual_start_hint
      ;;
  esac
fi

if [[ "$SERVICE_STARTED" == "1" ]]; then
  echo "==> status"
  wait_for_hub || exit 1
fi

cat <<EOF

Agent Ledger is installed.
  ledger CLI:   $SHIM
  ledger data:  $LEDGER   (git repository; delete nothing by hand)
  web UI:       http://ledger.localhost:$PORT/   (sign in: ledger open)

Optional: Claude Code hooks (adds entries to ~/.claude/settings.json only after you confirm).
Preview first, it writes nothing:
  node $(printf '%q' "$REPO/adapters/claude-code/install-hooks.mjs") --dry-run
Other agents can use the \`ledger\` CLI or the local HTTP API directly — see examples/.
EOF
