# Separate Attack Lab

This is a hostile relay sandbox. Production deployment is documented in
[DEPLOY.md](../docs/DEPLOY.md): use `APP_ENV=production`, your HTTPS `ALLOWED_ORIGINS`,
verified `FORWARDED_ALLOW_IPS`, `MAIN_SITE_ORIGIN`, and a strong `LAB_ACCESS_CODE`.
Production binds 0.0.0.0:$PORT, refuses main DATABASE_URL credentials and exposes no
TCP listener. An HttpOnly Secure access session is required before UI, assets,
controls or WebSocket admission. Both meta robots and X-Robots-Tag specify noindex.
`/healthz` checks the isolated DB. Locally set LAB_ACCESS_CODE to enable the gate.

This is a hostile relay sandbox. Run it separately from the real chat service:

```sh
.venv/bin/python -m attack_lab
# Open http://localhost:8090
# Optional local TLS transport for the normal Tkinter / CLI client:
.venv/bin/python -m attack_lab --port 8090 --tcp-port 5056
# Equivalent macOS launcher:
demo/start_demo.sh --lab --port 5056
```

The product has no attack flags, controls or UI. The dependency is one way:
`attack_lab` imports the real relay/core/gateway; product imports never load the lab.
Only the optional neutral `RelayCore.interceptor` is used to change forwarding.

## Run a demonstration

Start a lab session, Reset lab, then Connect victims. The accounts are `lab_alice`
and `lab_bob`, password `Lab-Password-1234!`; a third `lab_lockout` account is reserved
for the fixed brute-force demonstration. These are public sandbox credentials.
Private RSA identities are generated in the browser and wrapped with the real
keystore module. Only public PEM keys are uploaded.

Both victim panes load the exact production HTML and JavaScript bundle. The lab
controller fills normal login/composer forms; it never alters client verification.
There is a separate Vite console entry so lab controls cannot enter product assets.

| Attack | Operation and genuine detection |
|---|---|
| Tamper | Flip a ciphertext byte; victim rejects the GCM tag |
| Replay | Resend a captured envelope; nonce/freshness check rejects it |
| Drop | Suppress next chat; send a follow-up to reveal the hash-chain gap |
| Reorder | Hold one envelope, then send the next first; chain ordering fails |
| Inject | Insert random ciphertext/tag/nonce; GCM rejects the forged envelope |
| MITM | Arm before connecting; replace a public ECDH key while retaining its old signature; handshake verification aborts |
| Brute force | Wrong passwords against only `lab_lockout`; real guard locks it, and a real victim login shows rejection |

A final dropped message cannot be detected until another message arrives. RSA
signature verification still runs for validly decrypted messages; the relay lacks
the session key to construct a new GCM-valid forged signed payload. The feed shows
actual `security_alert` reports and real account lockouts, not inferred success.

The relay console allowlists routing/ciphertext and public handshake values. It
never receives chat plaintext or private/session keys. As in the real app, login
passwords terminate at the gateway and must use HTTPS outside localhost.

## Simple Mallory demo (message level)

The easiest live demo: Mallory sits on the *relay* and sees every chat message as ciphertext. He has
three buttons at the top, and the victims' own clients decide what happens. This is the message-level attack lab
(`attack_lab/relay.py`), not the TLS proxy below; the TLS demo stays available.

```bash
demo/start_demo.sh --mallory            # Alice, Bob and Mallory: three Chrome windows on this Mac
demo/start_demo.sh --mallory --lan      # Alice + Mallory on the Mac, Bob = your phone (URL + QR printed)
demo/stop_demo.sh
```

**5-line demo script**
1. Start it. In Alice's and Bob's windows choose *Create an identity* (e.g. `alice` / `bob`) and name the other as Peer. Alice sends "hello": Bob gets it, Mallory's list shows `alice → bob`, the time and only shortened ciphertext.
2. Click **TAMPER** at the top of Mallory's window ("Armed: TAMPER — waiting for next message"; click again to disarm). Alice sends "pay 500": Bob's window shows **"Message was altered in transit — rejected"**, the row is labelled TAMPERED and Mallory disarms itself.
3. Click **DROP**, Alice sends "lost" (row DROPPED, Bob sees nothing), then "next": Bob's window warns **"1 message missing"**.
4. Click **REPLAY**, Alice sends "once": Bob gets it once, then **"Duplicate or old message — rejected"** (row REPLAYED).
5. Any armed attack hits the next message from **either** user (try it from Bob). **Reset** clears the list, the feed and any armed attack.

How it works. One set of three buttons at the top (like the old Tk Attack Lab panel). A click arms that attack for the
**next chat message, from either user**; the button is highlighted and the banner says "Armed: … — waiting for next
message". It is one-shot: it disarms itself after firing, and clicking the armed button again disarms it. Rows are a
read-only list and only the attacked row gets a label. DROP and TAMPER are the lab relay's own `drop_next` / `tamper_next`; REPLAY delivers the next
message and then the identical envelope (same nonce) a second time. Normal messages pass untouched. **Nothing is
faked:** Mallory's feed only repeats what Bob's own client reports after its own checks (hash chain,
AES-GCM tag, nonce freshness), the same `security_alert` the client sends to the relay. Mallory's page lists
chat envelopes only, so call signalling and file messages also appear as rows (large ciphertext).

The messages travel through the lab relay (`attack_lab.simple`): the real web client served over HTTPS (or HTTP on
loopback in the tests), a throw-away SQLite database and attachment folder in a temp directory, never the real
database. Mallory's window listens on `127.0.0.1:8095` only (host/origin checked); with `--lan` the chat listens on
`127.0.0.1` and the Mac's private LAN address, and the certificate page on `<LAN IP>:8081`, exactly as in the
phone section below. The same demo CA (`data/network_attack/ca.crt`) is reused, so a phone that already installed
it needs nothing new. Product change made for this demo: the web client now shows the receiver's rejection reasons
in plain words in a warning box (`web/frontend/src/securityWarning.ts`) and scrolls to the newest message; the
checks themselves are unchanged. Tests: `npm --prefix web/frontend run test:mallory` (Playwright, Chromium and
WebKit: arming/disarming, each attack in the receiver's window, either direction, auto-disarm, Reset).

## Network attacker demo ("fake Wi-Fi")

Mallory controls the network between two real users and the real server, like a rogue
hotspot. This runs locally and shows what TLS does to a network attacker. It is
separate from the Attack Lab website above: there the *relay* is hostile (a different
threat, stopped by end-to-end crypto); here only the *network* is hostile.

```bash
demo/start_demo.sh --network-attack              # BROWSER demo (default): one command, no manual steps
demo/start_demo.sh --network-attack --desktop    # same with the Tkinter clients (server :5000, proxy :5001)
demo/start_demo.sh --network-attack --desktop --wireshark   # plus a live Wireshark capture
demo/stop_demo.sh                                # stops everything of ours, closes the demo Chrome windows
```

Browser demo ports: victims open **https://localhost:8443** (Mallory's proxy), the real
web gateway listens on 127.0.0.1:8444 over HTTPS/WSS, Mallory's window is
http://localhost:8095. Change them with `--proxy-port N` and `--mallory-port N`.

### The windows

| Window | What it is |
|---|---|
| **Alice** and **Bob** (default: two Google Chrome windows with their own throwaway profiles, so their sessions and keys are separate) | The web client served by the real gateway, opened on the proxied URL: every byte, including the WebSocket, goes through Mallory. With `--desktop` they are the Tkinter clients started with `--port <proxy port>`; they still pin `certs/server.crt`. |
| **Mallory** (Chrome, `http://localhost:8095`) | Live list of captured TLS records: direction, record type, size, first bytes in hex and as text (visibly unreadable), status. **Intercept ON/OFF**, per-record **Forward / Alter / Drop / Replay / Delay**, a feed of the real outcomes, the one-line lesson, **Open in Wireshark** and **Download .pcap**. |
| **Real gateway / server** | `uvicorn web.app:create_app` over TLS (`logs/demo_gateway.log`), or `server/server.py` with `--desktop`. Unchanged product code. |

**Local certificate, automatically.** The launcher generates a self-signed certificate for
`localhost` into `data/network_attack/` (git-ignored) with `python -m attack_lab.netproxy.webcert`.
If `mkcert` is installed *and* its local CA exists (`mkcert -install` once), it uses an mkcert
certificate instead and any browser trusts it. Otherwise the two demo Chrome windows are started
with `--ignore-certificate-errors-spki-list=<hash of exactly this public key>` and their own
`--user-data-dir`: no warning page, nothing added to the system trust store, no other certificate
becomes trusted. Opening the URL in your normal browser (or Safari) shows the usual self-signed
warning: click through once, or install mkcert. Google Chrome is required for the one-command mode.

Mallory's proxy (`python -m attack_lab.netproxy`) holds **no TLS key** and never
terminates TLS. It cuts the TCP byte stream into TLS records and relays them. Alter
flips one ciphertext byte, Drop withholds a record, Replay sends the same bytes a
second time, Delay holds a record. **The outcome is never simulated**: whatever
happens next is what the real TLS stacks of the browsers, gateway and server do; Mallory's
feed only reports which side closed the connection and how soon after the attack.

TLS 1.3 detail: after the ServerHello everything is wrapped as "Application Data", so
Mallory cannot even tell a chat message from a handshake message. The first
application-data record of each connection (TLS Finished) is always forwarded; with
Intercept ON, later records wait for your decision. After an Alter, Replay or Drop the
proxy switches Intercept OFF (checkbox "resume forwarding after an attack") because
otherwise Mallory would also be holding the TLS alert the victim sends back.

### Live review script

1. Run `demo/start_demo.sh --network-attack`. Say: "Alice and Bob think they talk to
   the server; Mallory is the Wi-Fi."
2. In Alice's and Bob's windows choose *Create an identity* (a name and a password) and name
   the other as Peer.
   Mallory's window fills with records. Point at the hex: nothing readable, not even
   the usernames or the password. (Optional: **Open in Wireshark**.)
3. Intercept **OFF**: Alice sends "hello". Bob receives it. Mallory forwarded
   untouched and read nothing.
4. Intercept **ON**, Alice sends "pay 500". A record is waiting. Press **Forward**
   (and Forward the server's copy towards Bob): delivered normally.
5. Alice sends again; press **Alter**. Mallory's feed shows `ALTER ... closed by the
   server ... bad_record_mac`. **Alice's window** loses its session ("Reconnecting… Session
   keys discarded. Login will be required."); with `--desktop` it shows the real error
   (`SSLError ... bad record mac`) and "Disconnected".
6. Log in again (Intercept ON), send, press **Replay** on that record: the original
   usually goes through, but the duplicate breaks the connection (TLS sequence numbers).
   Or use **Replay now** on any older record.
7. Send and press **Drop**: the message never arrives, nothing tells Alice
   (`STALLED` in the feed). Send another message: now the sequence numbers no longer
   match and the connection breaks.
8. **Delay** (3 s): the message arrives late but intact, because TLS only cares about
   order and integrity.
9. Lesson on the page: *TLS stops a network attacker: he sees only ciphertext, and any
   change breaks the connection.*

Things to say if asked: Mallory *can* still drop the connection or the traffic (TLS
does not give availability), and he can see sizes and timing (traffic analysis). He
cannot read or silently change anything. A malicious **server** is a different
problem, handled by the end-to-end layer (Attack Lab website).

### Phone as a victim (`--lan`)

```bash
demo/start_demo.sh --network-attack --lan            # auto-detect the Mac's LAN address
demo/start_demo.sh --network-attack --lan-ip 172.20.10.2   # or name it yourself
demo/stop_demo.sh                                    # closes the LAN listener too and says so
```

What it does, and what stays private:

| Item | Where it listens |
|---|---|
| Mallory's proxy | `127.0.0.1:8443` **and** `<LAN IP>:8443` (that one address, never `0.0.0.0`) |
| Certificate page for the phone (plain HTTP) | `<LAN IP>:8081`: only the instructions and the *public* CA certificate, private-network clients only |
| Real web gateway | `127.0.0.1:8444` only, behind the proxy |
| Mallory's control page | `127.0.0.1:8095` only |

The LAN address is found from the default route (`route get default` + `ipconfig getifaddr`), so it
works on ordinary Wi-Fi (`192.168.x.x` or `10.x.x.x`) and on an iPhone Personal Hotspot (the Mac gets
`172.20.10.x`). It is printed with its interface name. Only RFC 1918 private addresses are accepted;
anything else (including `0.0.0.0`) is refused. The terminal prints the phone URL and a QR code, the
certificate-page URL with its own QR code, and the CA's SHA-256 fingerprint (the page on the phone shows
the same value: compare them).

**Certificate.** With `--lan` the launcher builds a small demo CA (`data/network_attack/ca.crt`, key
`ca.key` mode 0600, git-ignored, never served) and signs the server certificate with the LAN IP,
`localhost`, `127.0.0.1` and `::1` in its SAN (EKU serverAuth, 90 days, so phones accept it). When you
join another network only the server certificate is reissued: **a phone that installed the CA once keeps
working**. If `mkcert` is installed and set up, its certificate is used and its public root is offered
instead.

#### Installing the demo CA on the phone (reliable path)

Open `http://<LAN IP>:8081/` on the phone (scan the second QR code); the page repeats these steps.

*iPhone (Safari)*
1. Tap **Download the demo CA certificate**, then **Allow** ("This website is trying to download a
   configuration profile").
2. **Settings** → **Profile Downloaded** (or **General → VPN & Device Management**) → *Secure Chat
   Network-Attack Demo CA* → **Install** → passcode → **Install** → **Install**.
3. **Settings → General → About → Certificate Trust Settings** → switch **on** full trust for
   *Secure Chat Network-Attack Demo CA* → **Continue**. (Without this step the profile is installed but
   not trusted for websites.)
4. Open `https://<LAN IP>:8443` in Safari: no warning.
5. Afterwards: **Settings → General → VPN & Device Management** → the profile → **Remove Profile**.

*Android (Chrome)*
1. Tap the download button (file `cns-demo-ca.crt`).
2. **Settings → Security & privacy → More security & privacy → Encryption & credentials → Install a
   certificate → CA certificate** (menu names vary by vendor: search Settings for "CA certificate"),
   **Install anyway**, pick the file. A screen lock is required.
3. Open `https://<LAN IP>:8443` in Chrome: no warning.
4. Afterwards: **Encryption & credentials → User credentials** → remove it.

#### The simpler path: just accept the warning

Open `https://<LAN IP>:8443` and accept the self-signed warning once (iPhone: *Show Details → visit this
website*; Android Chrome: *Advanced → Proceed*). **Whether WSS keeps working after only accepting could not
be tested here, because there is no phone in this environment.** What was verified: the page and the WebSocket
work over the LAN address when the certificate is trusted (Python `ssl` with the demo CA, and Chromium on a
phone-sized viewport with certificate errors ignored, which is *not* the same as a user pressing "proceed"),
and a client that does not trust the CA is refused. What to expect: Chrome stores the exception per host and
usually lets the WebSocket through; Safari on iPhone is known to refuse WebSocket connections to a host
whose certificate it does not trust even after you accepted the page warning, and microphone/crypto APIs
may need a trusted certificate. So: **on an iPhone install the CA; on Android try accepting first, and
install the CA if the chat stays on "Connection failed".**

#### If the phone cannot reach the Mac

Mallory's window has a **Phone on the LAN** box (URL, certificate page, devices seen). A device counts as
reached when it opens the certificate page or connects to the proxy. If nothing has reached the Mac after
60 s the box and the feed show a warning. Typical causes:

1. **Wi-Fi client isolation** (guest, hotel, campus or "AP isolation" Wi-Fi): devices on the same Wi-Fi are
   not allowed to talk to each other, so the phone can never reach the Mac. Use the fallback: turn on the
   iPhone **Personal Hotspot**, join it with the Mac (it gets `172.20.10.x`), run the command again and open the
   new URL on the phone (the iPhone itself reaches the Mac on that network). Mobile data on the phone does *not*
   work: it is a different network.
2. **macOS firewall.** The launcher reads the firewall state (read-only) and prints this when it is on. When
   macOS asks *"Do you want the application “python” to accept incoming network connections?"* click **Allow**.
   If you dismissed it: **System Settings → Network → Firewall → Options → “+”**, add the Python binary printed
   by the launcher (the real path behind `.venv/bin/python`), set it to **Allow incoming connections**, and make sure
   **Block all incoming connections** is off. As a last resort turn the firewall off for the demo and back on afterwards.
3. The phone is on another network than the Mac, a VPN is active on the Mac (the detected interface is
   printed), or the Mac's address changed: restart with `--lan`.

#### Phone review script

1. Mac and phone on the same Wi-Fi (or the Mac on the phone's hotspot). Run
   `demo/start_demo.sh --network-attack --lan`. Say: "Mallory is the Wi-Fi; the phone is a real victim."
2. Phone: scan the second QR code, install the CA (steps above, one time), then scan the first QR code. The
   chat page opens with no warning. Mallory's window shows *Phone on the LAN: devices seen* and the connection
   as **Phone 192.168.x.x**.
3. Phone: choose *Create an identity*, name the Mac's Alice window as Peer (and the reverse in Alice's window).
   Send a message each way. Mallory's table fills with unreadable records from both devices.
4. Mallory: **Intercept ON**, send from the phone, press **Alter**. The phone shows *Reconnecting… Session keys
   discarded. Login will be required.* and the feed shows the server closing the connection (the real TLS failure).
   Repeat with **Replay** and **Drop** (silent loss, then break on the next message).
5. **Delay** 3 s: the phone's message arrives late but intact.
6. Take a photo from the phone's gallery and send it; open **Download .pcap** or **Open in Wireshark**: only
   TLS records, no image bytes.
7. Voice call phone ↔ Mac works only with a trusted certificate (installed CA); the audio itself is peer to peer
   and never crosses the proxy, only the signalling does.
8. `demo/stop_demo.sh` ("LAN listeners on … closed"), then remove the CA from the phone.

Not verified here (no phone available): the actual install flow on iOS/Android, WSS after merely accepting the
warning, calls from a phone, and the behaviour behind real client-isolation Wi-Fi. Verified: LAN detection,
the private-address guard, certificate chain and SAN, that the proxy and certificate page listen on the LAN
address only (gateway and Mallory's page do not), the certificate page contents and fingerprint, HTTPS+WSS to
the LAN address with the demo CA, QR codes (decoded back with Apple's CoreImage reader), a phone-sized Chromium
chatting through the LAN address, and `stop_demo.sh` closing the listener.

### What a browser can and cannot show

Browsers hide TLS error details from page JavaScript: when Mallory breaks the WebSocket the page
only sees "closed", so the web client shows its own state ("Reconnecting… Session keys discarded.
Login will be required."), not the TLS alert. The browser's *own* stack does report it: with
Intercept ON, press **Alter** on a held request and open Chrome DevTools → Network: failed HTTPS
requests show `net::ERR_SSL_PROTOCOL_ERROR` (verified by the Playwright suite below). Chrome also retries
a failed request on a new connection by itself, so untick "resume forwarding after an attack" and
keep Intercept ON if you want to see that error. With `--desktop` the Tkinter window shows the
SSL error text directly.

Verified end to end with real headless Chromium through the proxy (`npm --prefix web/frontend run
test:netattack`): chat both ways, a photo, a voice call, no plaintext in Mallory's capture, and
Alter / Replay / Drop each breaking the real session. WebRTC audio is peer-to-peer and does **not**
pass through the proxy; only the call signalling (inside the WebSocket) does.

### Wireshark

**Open in Wireshark** writes the records Mallory captured to a `.pcap` (each record as one
TCP segment, bytes exactly as the proxy received them, decoded as TLS on the proxy port)
and opens it with the helper from `attack_lab/scripts/run_wireshark_demo.py`. It needs no
capture privileges. `--wireshark` additionally starts a live capture of the proxy port
before anything connects, so the handshakes are recorded too.

### Limits and honest notes

- Victim labels ("Alice", "Bob") are found with `lsof`: for Chrome from the `--user-data-dir`
  profile name in the process tree, for the Tkinter clients from `CNS_DEMO_LABEL`. Short-lived
  connections can stay "Client N".
- The web client reconnects by itself (and discards its session keys); the desktop GUI does not: after any attack that breaks TLS the
  victim shows "Disconnected ... restart to reconnect". A dropped message therefore
  stalls first and fails on the *next* message, as described above.
- `client/client.py` now passes the real exception text (for example the SSL error) into
  the "disconnected" event instead of the fixed text "connection lost". No protocol change.
- Tests: `tests/test_network_attacker.py` (pytest) and `web/frontend/e2e-netattack/` (Playwright).

## Isolation and configuration

- `$PORT` selects HTTP port (default 8090); `--port` overrides it. `--host` defaults
  to 127.0.0.1. No deployment or public exposure is performed by this phase.
- `LAB_DATABASE_URL`: default `sqlite:///<project>/data/attack_lab.db`. It is passed
  explicitly to user storage, lockout, relay persistence and logging. `DATABASE_URL`
  is never reassigned. PostgreSQL URLs use the same SQLAlchemy adapter.
- The lab refuses the configured/default production database, including resolved
  SQLite symlink/hardlink aliases and SQLite URI aliases. Use separate PostgreSQL
  databases and credentials. A trusted operator remains responsible for configuring
  distinct infrastructure; source/config changes by an administrator are outside
  this containment boundary.
- `LAB_STATE_DIR`: own JSONL log and TCP certificate/key directory; defaults to
  `data/attack_lab`. TCP clients must trust that directory's `certs/server.crt`
  using `SECURECHAT_CERT_DIR=<absolute-path>/data/attack_lab/certs`. Never replace
  the production certificate to connect to the lab.
- `LAB_ALLOWED_ORIGINS`: explicit comma-separated origins, default localhost and
  127.0.0.1 on the lab port; must be disjoint from `SECURECHAT_ALLOWED_ORIGINS`.
  Production retains its normal frame denial; only the lab permits same-origin
  victim embedding.
- Lab controls require a one-hour HttpOnly, SameSite=Strict session cookie; writes
  require exact Origin. Limits per minute: 10 session starts per source address,
  30 control writes per session, 120 state reads per session. There are no external
  host, URL or arbitrary account inputs to the brute-force endpoint.
- Reset closes sandbox connections, deletes lab DB rows except schema version,
  clears captures/armed actions/address limits and reseeds accounts. It leaves the
  independent production DB and roster untouched. Reset does not erase old JSONL
  audit lines or browser keystore backups.
- One process is one shared sandbox; visitors can affect each other's experiments.
  A session restricts controls to lab visitors, not to individually owned labs.
  Use a single worker. General web login/registration still uses the isolated DB.

Legacy authenticated localhost-only TCP `lab_control` exists only in the rogue
relay for compatible scripts. Production rejects this as an unknown envelope type.
The `demo/run_*_demo.py` wrappers now execute implementations under
`attack_lab/scripts/`; these use throwaway databases, logs, keys and exports.

## Build and verify

```sh
npm --prefix web/frontend ci
npm --prefix web/frontend run build
npm --prefix web/frontend run build:lab
.venv/bin/python -m pytest tests/ -q
npm --prefix web/frontend test
npm --prefix web/frontend run test:e2e
npm --prefix web/frontend run test:lab
.venv/bin/python tools/evaluate_security.py
```

The lab Playwright suite uses a temporary DB/state directory and seven real victim
flows. Its harness asserts that the production DB sentinel was never created.
Product HTML/JS byte equality, database isolation/reset, owner-independent lab
controls, request limits, import separation and unknown-type rejection are covered
by Python tests. The evaluator still performs 20 trials of each original category
(120 total) and checks false rejection on 200 normal messages.

Older GUI screenshots 01/03/04/05/09, evaluation screenshot 10,
`docs/history/full_walkthrough.md`, `docs/history/UI_REDESIGN_PROGRESS.md`, documentation PDFs and
local PowerPoint review files predate this separation. PDFs/PowerPoints were not
edited. Current usage is documented here and in the root README.
