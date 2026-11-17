#!/bin/bash
# One-command live demo: opens clearly titled Terminal windows for
#   1) the normal relay server
#   2) chat window A   3) chat window B   4) the security dashboard
# and the three GUI windows, arranged so none fully covers another.
#
#   demo/start_demo.sh               normal server on port 5000
#   demo/start_demo.sh --web       also serve the browser client on localhost:8080
#   demo/start_demo.sh --web-port N  choose the browser port
#   demo/start_demo.sh --lab         separate sandbox site on localhost:8090
#   demo/start_demo.sh --port 5055   use another port (e.g. if you prefer
#                                    to stay clear of macOS AirPlay on 5000)
#   demo/start_demo.sh --simple      NO extra windows: the server runs in the
#                                    background; you get only the two chat
#                                    windows (sender and receiver)
#   demo/start_demo.sh --wireshark   also start a live Wireshark capture of
#                                    the demo port BEFORE anything connects
#                                    (combine: --simple --wireshark)
#   demo/start_demo.sh --network-attack  "fake Wi-Fi" demo with the WEB client: HTTPS/WSS gateway
#                                    (127.0.0.1:8444) behind Mallory's TLS-blind proxy
#                                    (https://localhost:8443), two Chrome windows (Alice,
#                                    Bob) on the proxied URL and Mallory's window
#                                    (http://localhost:8095). No root, no manual steps.
#   demo/start_demo.sh --network-attack --lan   also make your PHONE a victim: the proxy listens on
#                                    the Mac's LAN IP (auto-detected, also an iPhone hotspot),
#                                    prints the phone URL + QR code and serves the demo CA at
#                                    http://<ip>:8081/. --lan-ip IP overrides the detection.
#   demo/start_demo.sh --mallory [--lan]   SIMPLE message-level attacker on the lab relay: Alice and
#                                    Bob chat on the web client, Mallory's window shows each
#                                    message as ciphertext with DROP / TAMPER / REPLAY. With --lan
#                                    Bob is your phone (phone URL + QR printed, demo CA page).
#   demo/start_demo.sh --network-attack --desktop   same with the Tkinter clients: server
#                                    on PORT, proxy on PORT+1. Add --wireshark for a live
#                                    capture. --proxy-port N changes the browser proxy port.
#   demo/start_demo.sh --presentation  Presentation mode in every GUI window
#                                    (~25% larger text, for a projector); you can
#                                    also toggle it in any window with Cmd+Shift+P
#
# Windows are tiled to fit THIS screen (demo/layout.py): two chat windows side by
# side, the dashboard below them and the server's Terminal window beside it, so
# nothing is hidden behind anything else.
#
# Stop it again with demo/stop_demo.sh. Double-clickable twin:
# demo/start_demo.command.
source "$(dirname "${BASH_SOURCE[0]}")/_demo_lib.sh"

PORT=5000
LAB=0
SIMPLE=0
WIRESHARK=0
NETATTACK=0
MALLORY=0
DESKTOP=0
LAN=0
LAN_IP_ARG=""
CERT_PORT=8081
PROXY_PORT_WEB=8443
MALLORY_PORT=8095
PRESENTATION=0
WEB_PORT=""
while [ $# -gt 0 ]; do
    case "$1" in
        --web) WEB_PORT=8080; shift ;;
        --web-port) [ $# -ge 2 ] || { echo "--web-port needs a number" >&2; exit 2; }; WEB_PORT="$2"; shift 2 ;;
        --lab) LAB=1; shift ;;
        --no-lab) LAB=0; shift ;;
        --simple) SIMPLE=1; shift ;;
        --network-attack) NETATTACK=1; shift ;;
        --mallory) MALLORY=1; shift ;;
        --desktop) DESKTOP=1; shift ;;
        --lan) LAN=1; shift ;;
        --lan-ip) LAN=1; LAN_IP_ARG="${2:-}"; shift 2 ;;
        --cert-port) CERT_PORT="${2:-}"; shift 2 ;;
        --proxy-port) PROXY_PORT_WEB="${2:-}"; shift 2 ;;
        --mallory-port) MALLORY_PORT="${2:-}"; shift 2 ;;
        --wireshark) WIRESHARK=1; shift ;;
        --presentation) PRESENTATION=1; shift ;;
        --port)   PORT="${2:-}"; shift 2 ;;
        -h|--help) sed -n '2,47p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *) echo "unknown option: $1 (try --help)" >&2; exit 2 ;;
    esac
done
case "$PORT" in ''|*[!0-9]*) echo "--port needs a number, got '$PORT'" >&2; exit 2 ;; esac
if [ "$MALLORY" = 1 ] && { [ "$NETATTACK" = 1 ] || [ "$DESKTOP" = 1 ]; }; then
    echo "--mallory is its own demo: use it without --network-attack/--desktop" >&2; exit 2
fi
if [ "$LAN" = 1 ] && { [ "$NETATTACK" = 0 ] && [ "$MALLORY" = 0 ] || [ "$DESKTOP" = 1 ]; }; then
    echo "--lan works with the browser demos only: use --mallory --lan or --network-attack --lan (the phone uses the web client)" >&2; exit 2
fi

if [ -n "$WEB_PORT" ] && [ "$LAB" = 0 ]; then
    case "$WEB_PORT" in *[!0-9]*) echo "--web-port needs a number" >&2; exit 2 ;; esac
    if [ "$WEB_PORT" -lt 1 ] || [ "$WEB_PORT" -gt 65535 ]; then echo "--web-port must be 1..65535" >&2; exit 2; fi
    if [ ! -f "$ROOT/web/static/index.html" ]; then echo "Build the browser client: cd web/frontend && npm ci && npm run build" >&2; exit 1; fi
    export SECURECHAT_ALLOWED_ORIGINS="${SECURECHAT_ALLOWED_ORIGINS:-http://localhost:$WEB_PORT,http://127.0.0.1:$WEB_PORT}"
    echo "Browser client: http://localhost:$WEB_PORT (shares the TCP roster)"
fi
cd "$ROOT" || exit 1
if [ ! -x "$PY" ]; then
    echo "No virtualenv at $ROOT/.venv. Create it first:" >&2
    echo "  python3 -m venv .venv && .venv/bin/pip install -r requirements.txt" >&2
    exit 1
fi
# shellcheck disable=SC1091
source "$ROOT/.venv/bin/activate"

if [ "$LAB" = 1 ]; then
    LAB_HTTP_PORT="${WEB_PORT:-${PORT_LAB:-8090}}"
    export LAB_ALLOWED_ORIGINS="${LAB_ALLOWED_ORIGINS:-http://localhost:$LAB_HTTP_PORT,http://127.0.0.1:$LAB_HTTP_PORT}"
    echo "ATTACK LAB — sandbox, not the real service"
    echo "Open http://localhost:$LAB_HTTP_PORT ; Ctrl+C stops the lab."
    echo "Optional local TCP relay: $PORT (trust data/attack_lab/certs/server.crt)."
    exec "$PY" -m attack_lab --port "$LAB_HTTP_PORT" --tcp-port "$PORT"
fi

echo "=== Secure Chat demo launcher ==="
echo "Project: $ROOT"
echo "[1/5] Stopping any previous demo of ours (server on port $PORT, chat windows, dashboard)"
stop_demo_processes "$PORT"

echo "[2/5] Checking the TLS certificate"
cert_check() {
    "$PY" - <<'PYEOF'
import datetime, ssl, sys
sys.path.insert(0, ".")
try:
    from certs.generate_certs import CERT_PATH, KEY_PATH, cert_fingerprint_from_file
    ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER).load_cert_chain(CERT_PATH, KEY_PATH)  # missing/corrupt/mismatched -> error
    from cryptography import x509
    cert = x509.load_pem_x509_certificate(open(CERT_PATH, "rb").read())
    expires = getattr(cert, "not_valid_after_utc", None) or cert.not_valid_after.replace(tzinfo=datetime.timezone.utc)
    if expires < datetime.datetime.now(datetime.timezone.utc):
        raise ValueError(f"certificate expired on {expires:%Y-%m-%d}")
    print(cert_fingerprint_from_file(CERT_PATH))
except Exception as exc:
    print(f"{type(exc).__name__}: {exc}", file=sys.stderr)
    sys.exit(1)
PYEOF
}
CERT_ERR="$(mktemp)"; trap 'rm -f "$CERT_ERR"' EXIT
if FP="$(cert_check 2>"$CERT_ERR")"; then
    echo "    certificate OK, fingerprint $FP"
else
    echo "    certificate problem ($(cat "$CERT_ERR")) -- regenerating with demo/reset_environment.py"
    "$PY" demo/reset_environment.py --port "$PORT" --yes || exit 1
    FP="$(cert_check)" || { echo "certificate still invalid after reset" >&2; exit 1; }
    echo "    certificate regenerated, fingerprint $FP"
fi

# --- window layout: tiled to the VISIBLE frame of this screen (menu bar and Dock excluded) ---
screen_frame() {
    osascript -l JavaScript -e 'ObjC.import("AppKit"); var s=$.NSScreen.mainScreen; var f=s.visibleFrame; var a=s.frame; [Math.round(f.origin.x), Math.round(a.size.height-(f.origin.y+f.size.height)), Math.round(f.size.width), Math.round(f.size.height)].join(" ")' 2>/dev/null
}
SCREEN="$(screen_frame)"
case "$SCREEN" in
    [0-9]*" "[0-9]*" "[0-9]*" "[0-9]*) ;;
    *) SCREEN="0 25 1280 775" ;;     # safe fallback if the screen cannot be queried
esac
PRESFLAG=""; LAYOUT_FLAGS=""
[ "$PRESENTATION" = 1 ] && { PRESFLAG="--presentation"; LAYOUT_FLAGS="--presentation"; }
[ "$SIMPLE" = 1 ] && LAYOUT_FLAGS="$LAYOUT_FLAGS --simple"
eval "$("$PY" demo/layout.py $SCREEN $LAYOUT_FLAGS)"
echo "    screen $SCREEN -> windows tiled$( [ "$OVERLAP" = 1 ] && echo " (screen too small to tile without overlap: click a title bar to raise a window)" )"

MODE="normal mode"
if [ "$NETATTACK" = 1 ] && [ "$DESKTOP" = 1 ]; then
    PROXY_PORT=$((PORT + 1))
    case "$MALLORY_PORT" in ''|*[!0-9]*) echo "--mallory-port needs a number" >&2; exit 2 ;; esac
    mkdir -p "$ROOT/logs"
    [ "$WIRESHARK" = 1 ] && { echo "Starting the Wireshark capture (on the proxy port)"; PORT_BACKUP=$PORT; PORT=$PROXY_PORT; start_wireshark; PORT=$PORT_BACKUP; }
    echo "[3/5] Starting the REAL server in the background (port $PORT)"
    nohup "$PY" -u server/server.py --port "$PORT" > "$ROOT/logs/demo_server.log" 2>&1 &
    "$PY" - "$PORT" <<'PYEOF' || { echo "The server did not start; see logs/demo_server.log" >&2; exit 1; }
import sys, time
sys.path.insert(0, ".")
from client.client import TLSSetupError, connect_tls
deadline = time.time() + 40
while time.time() < deadline:
    try:
        connect_tls("127.0.0.1", int(sys.argv[1]), on_cert_fingerprint=lambda fp: None).close(); sys.exit(0)
    except (TLSSetupError, OSError):
        time.sleep(0.4)
sys.exit(1)
PYEOF
    echo "[4/5] Starting Mallory's proxy (victims -> port $PROXY_PORT -> server $PORT) and his window"
    nohup "$PY" -u -m attack_lab.netproxy --upstream "127.0.0.1:$PORT" --listen-port "$PROXY_PORT" \
        --ui-port "$MALLORY_PORT" --identify > "$ROOT/logs/demo_netproxy.log" 2>&1 &
    for _ in $(seq 1 50); do
        curl -fs "http://localhost:$MALLORY_PORT/" >/dev/null 2>&1 && break; sleep 0.3
    done
    curl -fs "http://localhost:$MALLORY_PORT/" >/dev/null 2>&1 || { echo "Mallory's window did not start; see logs/demo_netproxy.log" >&2; exit 1; }
    echo "[5/5] Opening Alice and Bob (connected through the proxy) and Mallory's window"
    CNS_DEMO_LABEL=Alice nohup "$PY" gui/chat_gui.py --port "$PROXY_PORT" --geometry "$CHAT_A_GEOM" $PRESFLAG >/dev/null 2>&1 &
    CNS_DEMO_LABEL=Bob nohup "$PY" gui/chat_gui.py --port "$PROXY_PORT" --geometry "$CHAT_B_GEOM" $PRESFLAG >/dev/null 2>&1 &
    sleep 1; open "http://localhost:$MALLORY_PORT"
    cat <<MSG

=== Network attacker demo is running ===
 Real server    : 127.0.0.1:$PORT over TLS (log: logs/demo_server.log)
 Mallory proxy  : 127.0.0.1:$PROXY_PORT  - Alice and Bob connect HERE, not to the server
 Mallory window : http://localhost:$MALLORY_PORT  (records, Intercept, results, Wireshark)
 Alice / Bob    : the two chat windows. Register in each, naming the OTHER as Peer.
 Script         : attack_lab/README.md, "Network attacker demo".
 When finished  : demo/stop_demo.sh
MSG
    exit 0
fi
WEBFLAG=""
[ -n "$WEB_PORT" ] && WEBFLAG="--web-port $WEB_PORT"

wait_for_server() {
    "$PY" - "$PORT" "$WEB_PORT" <<'PYEOF'
import sys, time, urllib.request
sys.path.insert(0, ".")
from client.client import TLSSetupError, connect_tls
port, deadline, last = int(sys.argv[1]), time.time() + 40, None
while time.time() < deadline:
    try:
        connect_tls("127.0.0.1", port, on_cert_fingerprint=lambda fp: None).close()
        if sys.argv[2]:
            with urllib.request.urlopen("http://localhost:" + sys.argv[2] + "/", timeout=1) as response:
                if response.status != 200:
                    raise OSError("browser frontend is not ready")
        sys.exit(0)
    except (TLSSetupError, OSError) as exc:
        last = str(exc).splitlines()[0]
        time.sleep(0.4)
print(f"    server not ready after 40s: {last}", file=sys.stderr)
sys.exit(1)
PYEOF
}

start_wireshark() {
    # Live capture of loopback traffic on our port, started BEFORE any client
    # connects so the TLS handshakes are recorded. (The one-time "Decode As:
    # port 5000 = TLS" rule is stored in Wireshark's own config.)
    if [ ! -d /Applications/Wireshark.app ]; then
        echo "    Wireshark is not installed in /Applications -- skipping the capture" >&2
        return 0
    fi
    pgrep -x Wireshark >/dev/null && osascript -e 'tell application "Wireshark" to quit' >/dev/null 2>&1 && sleep 1
    open -n -a Wireshark --args -i lo0 -f "tcp port $PORT" -Y tls -k
    sleep 4
    echo "    Wireshark is capturing loopback port $PORT (filter: tls)"
}

# ---- helpers shared by the browser demos (variables are read when called) ----
open_chrome() {  # label  url  column  [extra flag]
    CNS_DEMO_LABEL="$1" nohup "$CHROME" --user-data-dir="$PROFILES/$1" --no-first-run --no-default-browser-check \
        --disable-features=WebRtcHideLocalIpsWithMdns --disable-search-engine-choice-screen \
        --window-position=$(( SX + 8 + $3 * (COLW + 8) )),$(( SY + 8 )) --window-size=$COLW,$COLH \
        $4 --new-window "$2" >/dev/null 2>&1 &
}
print_lan_info() {
    if ! lsof -nP -iTCP@"$LAN_IP":"$PROXY_PORT_WEB" -sTCP:LISTEN >/dev/null 2>&1; then
        echo "WARNING: nothing is listening on $LAN_IP:$PROXY_PORT_WEB; see logs/demo_netproxy.log" >&2
    fi
    CA_FP="$("$PY" -c "import sys;sys.path.insert(0,'.');from attack_lab.netproxy.certpage import ca_info;print(ca_info(open(sys.argv[1],'rb').read())[2])" "$ROOT/data/network_attack/ca.crt")"
    # Read-only query of the macOS application firewall (no sudo); unknown -> show the advice anyway.
    FWTXT="$(/usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate 2>/dev/null || true)"
    case "$FWTXT" in *"disabled"*|*"State = 0"*) FW=0 ;; *) FW=1 ;; esac
    PYREAL="$("$PY" -c 'import os,sys;print(os.path.realpath(sys.executable))')"
    echo
    echo "=== PHONE AS A VICTIM (LAN) ==="
    echo " Mac LAN address : $LAN_IP (interface $LAN_IFACE)"
    echo " Phone URL       : https://$LAN_IP:$PROXY_PORT_WEB"
    "$PY" -m attack_lab.netproxy.qr "https://$LAN_IP:$PROXY_PORT_WEB"
    echo " Certificate page: http://$LAN_IP:$CERT_PORT/   (install the demo CA on the phone)"
    "$PY" -m attack_lab.netproxy.qr "http://$LAN_IP:$CERT_PORT/"
    echo " CA fingerprint  : $CA_FP  (the page on the phone shows the same)"
    echo " Phone steps     : iPhone  - open the certificate page in Safari, download, Settings > Profile Downloaded > Install,"
    echo "                             then Settings > General > About > Certificate Trust Settings > enable full trust."
    echo "                   Android - open it in Chrome, download, Settings > search 'CA certificate' > install."
    echo "                   Or just open the Phone URL and accept the warning (Safari may still refuse the WebSocket)."
    echo " Phone cannot connect? Wi-Fi client isolation (guest/hotel/campus Wi-Fi) blocks phone-to-Mac traffic:"
    echo "                   turn on the iPhone Personal Hotspot, join it with the Mac, and run this command again."
    case "$FW" in
        1|2) echo " macOS firewall  : ${FWTXT:-state unknown (assume ON)}. When macOS asks 'Do you want the application \"python\" to accept incoming network"
             echo "                   connections?' click Allow. If you missed it: System Settings > Network > Firewall > Options >"
             echo "                   '+' > add $PYREAL > Allow incoming connections;"
             echo "                   (also make sure 'Block all incoming connections' is OFF)."
             [ "$MALLORY" = 1 ] || echo "                   Mallory's window also warns after 60 s if no phone has reached the Mac." ;;
    esac
    if [ "$MALLORY" = 1 ]; then echo " Mallory's window is on localhost only; only the chat and the certificate page face the LAN."
    else echo " The gateway stays on 127.0.0.1 behind the proxy; Mallory's window is localhost only."; fi
}

# ---- SIMPLE Mallory demo: message-level attacker on the lab relay, web chat for both users ----
if [ "$MALLORY" = 1 ]; then
    case "$MALLORY_PORT" in ''|*[!0-9]*) echo "--mallory-port needs a number" >&2; exit 2 ;; esac
    case "$CERT_PORT" in ''|*[!0-9]*) echo "--cert-port needs a number" >&2; exit 2 ;; esac
    PROXY_PORT_WEB="${PROXY_PORT_WEB:-8443}"   # the chat the victims open
    CHROME="/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"
    [ -f "$ROOT/web/static/index.html" ] || { echo "Build the browser client: cd web/frontend && npm ci && npm run build" >&2; exit 1; }
    [ -x "$CHROME" ] || { echo "Google Chrome is needed for this demo's local windows" >&2; exit 1; }
    mkdir -p "$ROOT/logs" "$ROOT/data/network_attack"
    echo "[3/5] Local HTTPS certificate"
    LAN_IP=""; LAN_IFACE=""; CERT_IP_FLAGS=""
    if [ "$LAN" = 1 ]; then
        LANOUT="$("$PY" -m attack_lab.netproxy.lan ${LAN_IP_ARG:+--ip "$LAN_IP_ARG"})" || { echo "    cannot use --lan: see the message above" >&2; exit 1; }
        read -r LAN_IP LAN_IFACE <<< "$LANOUT"
        CERT_IP_FLAGS="--ip $LAN_IP"
        echo "    Mac LAN address: $LAN_IP (interface $LAN_IFACE)"
    fi
    CERTOUT="$("$PY" -m attack_lab.netproxy.webcert --dir "$ROOT/data/network_attack" $CERT_IP_FLAGS)" || { echo "certificate generation failed" >&2; exit 1; }
    read -r CERT_MODE SPKI <<< "$CERTOUT"
    [ "$CERT_MODE" = mkcert ] && echo "    mkcert certificate (your browser trusts it)" || echo "    demo CA certificate (the local Chrome windows accept exactly this key; install the CA on a phone via the printed page)"
    echo "[4/5] Starting the lab relay: web chat on https://localhost:$PROXY_PORT_WEB and Mallory's window on http://localhost:$MALLORY_PORT"
    nohup "$PY" -u -m attack_lab.simple --port "$PROXY_PORT_WEB" --mallory-port "$MALLORY_PORT" \
        --cert "$ROOT/data/network_attack/web.crt" --key "$ROOT/data/network_attack/web.key" \
        ${LAN_IP:+--lan-ip "$LAN_IP" --ca-cert "$ROOT/data/network_attack/ca.crt" --cert-port "$CERT_PORT"} \
        > "$ROOT/logs/demo_mallory.log" 2>&1 &
    "$PY" - "$PROXY_PORT_WEB" "$MALLORY_PORT" "$LAN_IP" "$CERT_PORT" <<'PYEOF' || { echo "The demo did not start; see logs/demo_mallory.log" >&2; exit 1; }
import ssl, sys, time, urllib.request
chat, ui, lan, cert_port = int(sys.argv[1]), int(sys.argv[2]), sys.argv[3], sys.argv[4]
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
deadline, ok = time.time() + 40, False
while time.time() < deadline and not ok:
    try:
        urllib.request.urlopen(f"http://localhost:{ui}/", timeout=1).read()
        urllib.request.urlopen(f"https://127.0.0.1:{chat}/", timeout=2, context=ctx).read()
        if lan:
            urllib.request.urlopen(f"http://{lan}:{cert_port}/", timeout=2).read()
            urllib.request.urlopen(f"https://{lan}:{chat}/", timeout=2, context=ctx).read()
        ok = True
    except OSError:
        time.sleep(0.4)
sys.exit(0 if ok else 1)
PYEOF
    echo "[5/5] Opening the windows"
    PROFILES="$(mktemp -d "${TMPDIR:-/tmp}/cns-netattack.XXXXXX")"
    echo "$PROFILES" > "$ROOT/logs/demo_netattack_profiles"
    read -r SX SY SW SH <<< "$SCREEN"
    NCOLS=3; [ -n "$LAN_IP" ] && NCOLS=2
    COLW=$(( (SW - (NCOLS + 1) * 8) / NCOLS )); COLH=$(( SH - 16 ))
    SPKIFLAG=""; [ "$CERT_MODE" = selfsigned ] && SPKIFLAG="--ignore-certificate-errors-spki-list=$SPKI"
    open_chrome Alice "https://localhost:$PROXY_PORT_WEB/" 0 "$SPKIFLAG"
    if [ -n "$LAN_IP" ]; then
        open_chrome Mallory "http://localhost:$MALLORY_PORT/" 1 ""
    else
        open_chrome Bob "https://localhost:$PROXY_PORT_WEB/" 1 "$SPKIFLAG"
        open_chrome Mallory "http://localhost:$MALLORY_PORT/" 2 ""
    fi
    cat <<MSG

=== Simple Mallory demo is running ===
 Chat           : https://localhost:$PROXY_PORT_WEB   (the real web client, served by the lab relay; logs/demo_mallory.log)
 Mallory window : http://localhost:$MALLORY_PORT      (DROP / TAMPER / REPLAY on each message, Reset)
 Alice$( [ -z "$LAN_IP" ] && echo " and Bob" )          : $( [ -z "$LAN_IP" ] && echo "two Chrome windows" || echo "the Chrome window on this Mac (Bob is your phone)" ). Create an identity in each, naming the OTHER as Peer.
 How to attack  : send one normal message first, click DROP / TAMPER / REPLAY on its row, then send the NEXT message.
 Script         : attack_lab/README.md, "Simple Mallory demo".
 When finished  : demo/stop_demo.sh
MSG
    [ -n "$LAN_IP" ] && print_lan_info
    exit 0
fi

if [ "$NETATTACK" = 1 ]; then
    case "$CERT_PORT" in ''|*[!0-9]*) echo "--cert-port needs a number" >&2; exit 2 ;; esac
    case "$PROXY_PORT_WEB" in ''|*[!0-9]*) echo "--proxy-port needs a number" >&2; exit 2 ;; esac
    case "$MALLORY_PORT" in ''|*[!0-9]*) echo "--mallory-port needs a number" >&2; exit 2 ;; esac
    GW_PORT=$((PROXY_PORT_WEB + 1))
    CHROME="/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"
    [ -f "$ROOT/web/static/index.html" ] || { echo "Build the browser client: cd web/frontend && npm ci && npm run build" >&2; exit 1; }
    [ -x "$CHROME" ] || { echo "Google Chrome is needed for the browser demo (or use --network-attack --desktop)" >&2; exit 1; }
    mkdir -p "$ROOT/logs" "$ROOT/data/network_attack"
    [ "$WIRESHARK" = 1 ] && { echo "Starting the Wireshark capture (on the proxy port)"; PORT_BACKUP=$PORT; PORT=$PROXY_PORT_WEB; start_wireshark; PORT=$PORT_BACKUP; }
    echo "[3/5] Local HTTPS certificate"
    LAN_IP=""; LAN_IFACE=""; CERT_IP_FLAGS=""
    if [ "$LAN" = 1 ]; then
        LANOUT="$("$PY" -m attack_lab.netproxy.lan ${LAN_IP_ARG:+--ip "$LAN_IP_ARG"})" || { echo "    cannot use --lan: see the message above" >&2; exit 1; }
        read -r LAN_IP LAN_IFACE <<< "$LANOUT"
        CERT_IP_FLAGS="--ip $LAN_IP"
        echo "    Mac LAN address: $LAN_IP (interface $LAN_IFACE)"
    fi
    CERTOUT="$("$PY" -m attack_lab.netproxy.webcert --dir "$ROOT/data/network_attack" $CERT_IP_FLAGS)" || { echo "certificate generation failed" >&2; exit 1; }
    read -r CERT_MODE SPKI <<< "$CERTOUT"
    if [ "$CERT_MODE" = mkcert ]; then
        echo "    mkcert certificate (your browser trusts it)"
    else
        echo "    self-signed certificate; the demo Chrome windows accept exactly this one key"
        echo "    (own throwaway profiles, nothing is added to your system trust store)"
    fi
    echo "[4/5] Starting the HTTPS/WSS gateway (127.0.0.1:$GW_PORT) behind Mallory's proxy (https://localhost:$PROXY_PORT_WEB)"
    ORIGINS="https://localhost:$PROXY_PORT_WEB,https://127.0.0.1:$PROXY_PORT_WEB"
    [ -n "$LAN_IP" ] && ORIGINS="$ORIGINS,https://$LAN_IP:$PROXY_PORT_WEB"
    SECURECHAT_ALLOWED_ORIGINS="$ORIGINS" \
        nohup "$PY" -u -m uvicorn --factory web.app:create_app --host 127.0.0.1 --port "$GW_PORT" \
        --ssl-certfile "$ROOT/data/network_attack/web.crt" --ssl-keyfile "$ROOT/data/network_attack/web.key" \
        --no-proxy-headers --ws-max-size 65536 --workers 1 > "$ROOT/logs/demo_gateway.log" 2>&1 &
    nohup "$PY" -u -m attack_lab.netproxy --upstream "127.0.0.1:$GW_PORT" --listen-port "$PROXY_PORT_WEB" \
        --ui-port "$MALLORY_PORT" --identify \
        ${LAN_IP:+--lan-ip "$LAN_IP" --ca-cert "$ROOT/data/network_attack/ca.crt" --cert-port "$CERT_PORT"} \
        > "$ROOT/logs/demo_netproxy.log" 2>&1 &
    "$PY" - "$GW_PORT" "$MALLORY_PORT" "$ROOT/data/network_attack/web.crt" "$LAN_IP" "$CERT_PORT" <<'PYEOF' || { echo "Gateway or Mallory's window did not start; see logs/demo_gateway.log and logs/demo_netproxy.log" >&2; exit 1; }
import ssl, sys, time, urllib.request
gw, ui, cert, lan, cert_port = int(sys.argv[1]), int(sys.argv[2]), sys.argv[3], sys.argv[4], sys.argv[5]
ctx = ssl.create_default_context(cafile=cert) if cert else None
deadline, ok = time.time() + 40, False
while time.time() < deadline and not ok:
    try:
        urllib.request.urlopen(f"http://localhost:{ui}/", timeout=1).read()
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
        urllib.request.urlopen(f"https://127.0.0.1:{gw}/", timeout=2, context=ctx).read()
        if lan:
            urllib.request.urlopen(f"http://{lan}:{cert_port}/", timeout=2).read()
        ok = True
    except OSError:
        time.sleep(0.4)
sys.exit(0 if ok else 1)
PYEOF
    echo "[5/5] Opening Alice and Bob (Chrome, through the proxy) and Mallory's window"
    PROFILES="$(mktemp -d "${TMPDIR:-/tmp}/cns-netattack.XXXXXX")"
    echo "$PROFILES" > "$ROOT/logs/demo_netattack_profiles"
    read -r SX SY SW SH <<< "$SCREEN"
    COLW=$(( (SW - 4 * 8) / 3 )); COLH=$(( SH - 16 ))
    SPKIFLAG=""; [ "$CERT_MODE" = selfsigned ] && SPKIFLAG="--ignore-certificate-errors-spki-list=$SPKI"
    open_chrome Alice "https://localhost:$PROXY_PORT_WEB/" 0 "$SPKIFLAG"
    open_chrome Bob "https://localhost:$PROXY_PORT_WEB/" 1 "$SPKIFLAG"
    open_chrome Mallory "http://localhost:$MALLORY_PORT/" 2 ""
    cat <<MSG

=== Network attacker demo (browser) is running ===
 Gateway        : https://127.0.0.1:$GW_PORT (the real web gateway, logs/demo_gateway.log)
 Mallory proxy  : https://localhost:$PROXY_PORT_WEB  - Alice and Bob open THIS URL
 Mallory window : http://localhost:$MALLORY_PORT  (records, Intercept, results, Wireshark)
 Alice / Bob    : two Chrome windows. Create an identity in each, naming the OTHER as Peer.
                  Photos and voice calls work too (allow the microphone for calls).
 Script         : attack_lab/README.md, "Network attacker demo".
 When finished  : demo/stop_demo.sh   (also closes the demo Chrome windows)
MSG
    [ -n "$LAN_IP" ] && print_lan_info
    exit 0
fi

if [ "$SIMPLE" = 1 ]; then
    # Only the two chat windows. Server runs quietly in the background; its
    # output goes to logs/demo_server.log. Stop with demo/stop_demo.sh.
    mkdir -p "$ROOT/logs"
    if [ "$WIRESHARK" = 1 ]; then echo "[3/5] Starting the Wireshark capture"; start_wireshark; fi
    echo "[4/5] Starting the server in the background ($MODE, port $PORT)"
    nohup "$PY" -u server/server.py $WEBFLAG --port "$PORT" > "$ROOT/logs/demo_server.log" 2>&1 &
    if ! wait_for_server; then
        echo "The server did not start; see logs/demo_server.log" >&2; exit 1
    fi
    echo "    server is up and its certificate matches certs/server.crt"
    echo "[5/5] Opening the sender and receiver windows"
    nohup "$PY" gui/chat_gui.py --port "$PORT" --geometry "$CHAT_A_GEOM" $PRESFLAG >/dev/null 2>&1 &
    nohup "$PY" gui/chat_gui.py --port "$PORT" --geometry "$CHAT_B_GEOM" $PRESFLAG >/dev/null 2>&1 &
    cat <<MSG

=== Demo is running (simple mode) ===
 Server  : 127.0.0.1:$PORT over TLS, cert fingerprint $FP, $MODE (background)
 Windows : the two chat windows (left = sender, right = receiver)$( [ "$WIRESHARK" = 1 ] && echo ", plus Wireshark" )
 Next    : Register a user in each window (name the OTHER as Peer), send a
           message$( [ "$WIRESHARK" = 1 ] && echo ", then look at Wireshark: Client Hello / Server Hello, then unreadable Application Data" ).
 Finish  : demo/stop_demo.sh   (Wireshark is left open; stop its capture yourself)
MSG
    exit 0
fi

[ "$WIRESHARK" = 1 ] && { echo "Starting the Wireshark capture"; start_wireshark; }

open_terminal() {  # title  command  x1 y1 x2 y2
    # `activate` first: otherwise Terminal's "front window" can still be an
    # OLDER window, and the bounds below would land on the wrong one.
    osascript >/dev/null <<OSA
tell application "Terminal"
    activate
    set t to do script "clear; cd '$ROOT' && source .venv/bin/activate && clear && $2"
    try
        set custom title of t to "$1"
    end try
    set bounds of front window to {$3, $4, $5, $6}
end tell
OSA
}

echo "[3/5] Opening the server window ($MODE, port $PORT)"
open_terminal "$TITLE_PREFIX · Server (port $PORT)" "SECURECHAT_ALLOWED_ORIGINS='http://localhost:${WEB_PORT:-8080},http://127.0.0.1:${WEB_PORT:-8080}' python server/server.py $WEBFLAG --port $PORT" $SERVER_BOUNDS

echo "[4/5] Waiting for the server to accept TLS connections"
if ! wait_for_server
then
    echo "The server window shows why. Fix that, then run this again (or demo/stop_demo.sh)." >&2
    exit 1
fi
echo "    server is up and its certificate matches certs/server.crt"

echo "[5/5] Opening chat windows A and B and the security dashboard"
nohup "$PY" gui/chat_gui.py --port "$PORT" --geometry "$CHAT_A_GEOM" $PRESFLAG >/dev/null 2>&1 &
nohup "$PY" gui/chat_gui.py --port "$PORT" --geometry "$CHAT_B_GEOM" $PRESFLAG >/dev/null 2>&1 &
nohup "$PY" gui/security_dashboard.py --geometry "$DASH_GEOM" $PRESFLAG >/dev/null 2>&1 &

cat <<MSG

=== Demo is running ===
 Server        : 127.0.0.1:$PORT over TLS, cert fingerprint $FP, $MODE
 Windows       : chat A (top-left), chat B (top-right), the security dashboard
                 (bottom-left) and the server's Terminal window (bottom-right),
                 tiled to this screen so nothing is hidden.
 What to do    : in window A log in (or Register) as one user and name the
                 OTHER user as "Peer"; in window B do the reverse. Once both
                 show a fingerprint, send a message, click a bubble for its
                 security receipt.
 Projector     : Cmd+Shift+P toggles Presentation mode in any window
                 (or start with demo/start_demo.sh --presentation).
 When finished : demo/stop_demo.sh   (stops only our server and windows)
MSG
