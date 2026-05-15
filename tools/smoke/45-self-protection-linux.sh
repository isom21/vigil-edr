#!/usr/bin/env bash
# 40-self-protection-linux.sh — verifies the M7.1 BPF LSM
# self-protection on a Linux host running the vigil-agent.
#
# Run from anywhere; expects systemctl, sudo, and the agent already
# installed and running. Emits a one-line PASS/FAIL summary at the end
# and a non-zero exit code on any failure.
#
# Usage:
#   tools/smoke/40-self-protection-linux.sh [--state-dir /var/lib/vigil]
set -uo pipefail

STATE_DIR="${VIGIL_STATE_DIR:-/var/lib/vigil}"
PIN_DIR="${VIGIL_PIN_DIR:-/sys/fs/bpf/vigil}"
while [ $# -gt 0 ]; do
    case "$1" in
        --state-dir) STATE_DIR="$2"; shift 2 ;;
        --pin-dir) PIN_DIR="$2"; shift 2 ;;
        *) echo "unknown arg: $1" >&2; exit 2 ;;
    esac
done

PID=$(pgrep -x vigil-agent | head -n1 || true)
if [ -z "$PID" ]; then
    # LIVE-8: distinguish "binary missing" (operator hasn't built /
    # installed the agent yet) from "binary present but not running"
    # (service exited or `cargo build` ran but `install-vigil.sh`
    # didn't). The fix is operator-side either way, so give them the
    # exact next step.
    REPO_ROOT="$(git rev-parse --show-toplevel 2>/dev/null || echo .)"
    if [ ! -x "$REPO_ROOT/target/release/vigil-agent" ]; then
        echo "FAIL: vigil-agent not running (and binary not built)"
        echo "      run: cargo build -p agent-linux --release && sudo install-vigil.sh"
    else
        echo "FAIL: vigil-agent not running"
        echo "      run: sudo systemctl start vigil-agent (or install-vigil.sh on first run)"
    fi
    exit 1
fi
echo "vigil-agent pid=$PID  state=$STATE_DIR  pins=$PIN_DIR"

fails=0
pass() { echo "  ok   - $1"; }
fail() { echo "  FAIL - $1"; fails=$((fails+1)); }

# 1. kill (root) blocked.
if sudo kill -9 "$PID" 2>/dev/null; then
    fail "kill -9 was NOT blocked"
else
    pass "kill -9 from root blocked"
fi
sleep 0.3
# Use /proc/<pid> presence rather than kill -0 — kill -0 also routes
# through lsm/task_kill and returns EPERM for non-self callers, which
# would falsely look like "process gone".
if [ ! -d "/proc/$PID" ]; then
    fail "agent died after blocked kill"
    exit 1
fi

# 2. ptrace via /proc/<pid>/mem blocked.
if sudo head -c 8 "/proc/$PID/mem" >/dev/null 2>&1; then
    fail "/proc/$PID/mem read was NOT blocked"
else
    pass "/proc/<pid>/mem read blocked"
fi

# 3. unlink under state dir blocked. Use a scratch path so we don't
#    risk losing real state if the test is run before self-protection
#    is fully primed.
SCRATCH="$STATE_DIR/.smoke-scratch-$$"
sudo touch "$SCRATCH" 2>/dev/null
if sudo rm -f "$SCRATCH" 2>/dev/null && [ ! -e "$SCRATCH" ]; then
    fail "unlink under $STATE_DIR was NOT blocked"
else
    pass "unlink under $STATE_DIR blocked"
fi
# Best-effort cleanup the scratch (allowed only by the agent's tgid;
# operator should remove it manually after the test).

# 4. unlink under bpffs pin dir blocked. bpffs mounts at mode 700 so we
#    need sudo even to stat individual entries.
if sudo test -e "$PIN_DIR/links/handle_task_kill"; then
    if sudo rm -f "$PIN_DIR/links/handle_task_kill" 2>/dev/null \
        && ! sudo test -e "$PIN_DIR/links/handle_task_kill"; then
        fail "unlink under $PIN_DIR was NOT blocked"
    else
        pass "unlink under $PIN_DIR blocked"
    fi
else
    fail "$PIN_DIR/links/handle_task_kill missing — pinning failed?"
fi

# 5. bpftool link detach blocked. Find one of our LSM link ids and try
#    to detach. Skip if bpftool is unavailable.
if command -v bpftool >/dev/null 2>&1; then
    LSM_LINK_ID=$(sudo bpftool -j link show 2>/dev/null \
        | python3 -c 'import json,sys; ls=json.load(sys.stdin); [print(l["id"]) for l in ls if l.get("prog_type")=="lsm"][:1]' \
        | head -n1)
    if [ -n "${LSM_LINK_ID:-}" ]; then
        if sudo bpftool link detach id "$LSM_LINK_ID" 2>/dev/null; then
            fail "bpftool link detach was NOT blocked"
        else
            pass "bpftool link detach blocked"
        fi
    else
        echo "  skip - no LSM link id found via bpftool"
    fi

    # 5.b: agent_self map hijack. The original M7.1 hook left
    # BPF_MAP_UPDATE_ELEM out of the block list so the takeover dance
    # could overwrite the slot from the new agent's tgid. That was
    # also the entry point for the reviewer's hijack:
    #   bpftool map update id <X> key 0 0 0 0 value <attacker_tgid_le>
    # Now that update must be rejected by lsm/bpf when called from a
    # non-self tgid while an agent is running. The auto-clear in
    # handle_sched_exit keeps legitimate restart working without this
    # carve-out.
    SELF_MAP_ID=$(sudo bpftool -j map show pinned "$PIN_DIR/maps/agent_self" 2>/dev/null \
        | python3 -c 'import json,sys; print(json.load(sys.stdin).get("id",""))')
    if [ -n "${SELF_MAP_ID:-}" ]; then
        ATTACKER_TGID=$$
        # Little-endian 4-byte encoding of the test tgid. Format string
        # is "0xAA 0xBB 0xCC 0xDD" so bpftool can splat the bytes.
        ATTACKER_VAL=$(python3 -c "import struct,sys; print(' '.join(f'{b:#04x}' for b in struct.pack('<I', $ATTACKER_TGID)))")
        if sudo bpftool map update id "$SELF_MAP_ID" key 0x00 0x00 0x00 0x00 \
                value $ATTACKER_VAL 2>/dev/null; then
            fail "bpftool map update on agent_self was NOT blocked"
            # Restore agent_self to the agent's tgid so the rest of
            # the test doesn't see a broken self_tgid().
            AGENT_VAL=$(python3 -c "import struct,sys; print(' '.join(f'{b:#04x}' for b in struct.pack('<I', $PID)))")
            sudo bpftool map update id "$SELF_MAP_ID" key 0x00 0x00 0x00 0x00 \
                value $AGENT_VAL 2>/dev/null || true
        else
            pass "bpftool map update on agent_self blocked (EPERM)"
        fi
    else
        echo "  skip - $PIN_DIR/maps/agent_self not pinned"
    fi
else
    echo "  skip - bpftool not installed"
fi

# 6. systemctl stop succeeds (init carve-out).
if sudo systemctl stop vigil-agent 2>/dev/null; then
    pass "systemctl stop succeeds"
    sudo systemctl start vigil-agent
    sleep 3
else
    fail "systemctl stop failed (init carve-out broken?)"
fi

if [ "$fails" -eq 0 ]; then
    echo "PASS - all self-protection checks blocked from non-self caller"
    exit 0
else
    echo "FAIL - $fails self-protection check(s) leaked"
    exit 1
fi
