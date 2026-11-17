# Shared helpers for demo/start_demo.sh and demo/stop_demo.sh (sourced, not run).
#
# SAFETY RULE: these helpers only ever touch processes that are OURS, meaning
# the command line is one of this project's entry points AND its working
# directory is this project's root. macOS's AirPlay Receiver (ControlCenter)
# also listens on port 5000 -- it is never matched, never signalled.

DEMO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$DEMO_DIR/.." && pwd)"
PY="$ROOT/.venv/bin/python"
TITLE_PREFIX="Secure Chat Demo"

proc_cwd() { lsof -a -p "$1" -d cwd -Fn 2>/dev/null | sed -n 's/^n//p' | head -1; }

# our_pids <extended-regex>: PIDs whose command matches AND whose cwd is ROOT
our_pids() {
    local pid
    for pid in $(pgrep -f "$1" 2>/dev/null); do
        [ "$pid" = "$$" ] && continue
        [ "$(proc_cwd "$pid")" = "$ROOT" ] && echo "$pid"
    done
}

# our_server_pids_on_port <port>: our server.py processes LISTENing on <port>
our_server_pids_on_port() {
    local pid
    for pid in $(lsof -nP -iTCP:"$1" -sTCP:LISTEN -t 2>/dev/null | sort -u); do
        ps -p "$pid" -o command= 2>/dev/null | grep -Eq "server/server\.py| -m attack_lab( |$)" || continue
        [ "$(proc_cwd "$pid")" = "$ROOT" ] && echo "$pid"
    done
}

# stop_pids <pid>...: polite SIGTERM, then SIGKILL for stragglers
stop_pids() {
    [ $# -gt 0 ] || return 0
    kill -TERM "$@" 2>/dev/null
    local i p alive
    for i in 1 2 3 4 5 6; do
        alive=0
        for p in "$@"; do kill -0 "$p" 2>/dev/null && alive=1; done
        [ "$alive" = 0 ] && return 0
        sleep 0.5
    done
    kill -KILL "$@" 2>/dev/null
    return 0
}

# close the Terminal windows this demo opened (identified by their title)
close_demo_terminals() {
    pgrep -x Terminal >/dev/null 2>&1 || return 0   # don't launch Terminal just to close windows
    osascript >/dev/null 2>&1 <<OSA
tell application "Terminal"
    set doomed to {}
    repeat with w in windows
        try
            if (custom title of selected tab of w) starts with "$TITLE_PREFIX" then set end of doomed to (id of w)
        end try
    end repeat
    repeat with i in doomed
        try
            close (first window whose id is i) saving no
        end try
    end repeat
end tell
OSA
    return 0
}

# stop_demo_processes [port]: our server (only on <port> if given, else any
# port), plus our chat windows and dashboard. Prints what it stopped.
stop_demo_processes() {
    local port="${1:-}" servers guis
    if [ -n "$port" ]; then servers="$(our_server_pids_on_port "$port")"
    else servers="$(our_pids 'server/server\.py| -m attack_lab( |$)')"; fi
    guis="$(our_pids 'gui/chat_gui\.py|gui/security_dashboard\.py')"
    local all proxies gateways browsers
    proxies="$(our_pids ' -m attack_lab\.(netproxy|simple)( |$)')"
    gateways="$(our_pids 'uvicorn --factory web\.app:create_app')"
    # Demo Chrome windows are identified by their throwaway profile directory, never by name.
    browsers="$(pgrep -f 'user-data-dir=[^ ]*cns-netattack' 2>/dev/null)"
    all="$(printf '%s\n%s\n%s\n%s\n%s\n' "$servers" "$guis" "$proxies" "$gateways" "$browsers" | grep -E '^[0-9]+$' | sort -un | tr '\n' ' ')"
    # A proxy started with --lan also listens on the Mac's LAN address: remember it to confirm it closed.
    local lanpids lanip=""
    lanpids="$(our_pids ' -m attack_lab\.(netproxy|simple) .*--lan-ip')"
    [ -n "$lanpids" ] && lanip="$(ps -p "$(echo "$lanpids" | head -1)" -o command= | sed -n 's/.*--lan-ip \([0-9.]*\).*/\1/p')"
    if [ -n "$all" ]; then
        echo "    stopping our process(es): $all"
        # shellcheck disable=SC2086
        stop_pids $all
        if [ -n "$lanip" ]; then
            if lsof -nP -iTCP@"$lanip" -sTCP:LISTEN 2>/dev/null | grep -q .; then
                echo "    WARNING: something still listens on the LAN address $lanip (see: lsof -nP -iTCP@$lanip -sTCP:LISTEN)"
            else
                echo "    LAN listeners on $lanip closed"
            fi
        fi
    else
        echo "    no leftover demo processes of ours"
    fi
    close_demo_terminals
    local profiles="$ROOT/logs/demo_netattack_profiles"
    if [ -f "$profiles" ]; then
        local dir; dir="$(cat "$profiles")"
        case "$dir" in */cns-netattack.*) sleep 1; rm -rf "$dir" ;; esac
        rm -f "$profiles"
    fi
}
