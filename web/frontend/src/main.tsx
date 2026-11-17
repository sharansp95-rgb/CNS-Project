import React, { useState, useRef } from "react";
import { createRoot } from "react-dom/client";
import { identity, privateKey } from "./crypto";
import { Session, type Envelope, type Message } from "./session";
import { wrap, unwrap, loadBackup, saveBackup, type Backup } from "./keystore";
import "./style.css";
import { PublicVerify, EvidencePanel } from "./ProofUI";
import { CallButton, CallOverlay, callLogEntry } from "./CallUI";
import {
  AttachmentCard,
  Lightbox,
  asDescriptor,
  stageText,
} from "./AttachmentUI";
import type { Progress, OpenedAttachment } from "./session";

function download(name: string, body: unknown) {
  const url = URL.createObjectURL(
    new Blob([JSON.stringify(body, null, 2) + "\n"], {
      type: "application/json",
    }),
  );
  const a = document.createElement("a");
  a.href = url;
  a.download = name;
  a.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}
function App() {
  const [evidenceMode, setEvidenceMode] = useState<"save" | "list" | null>(
    location.pathname === "/evidence" ? "list" : null,
  );
  const sessionRef = useRef<Session | undefined>(undefined);
  const [username, setUsername] = useState(""),
    [peer, setPeer] = useState(""),
    [password, setPassword] = useState("");
  const [session, setSession] = useState<Session>(),
    [backup, setBackup] = useState<Backup>();
  const [busy, setBusy] = useState(false),
    [error, setError] = useState(""),
    [message, setMessage] = useState(""),
    [receipt, setReceipt] = useState<Envelope>();
  const [wire, setWire] = useState(false),
    [, refresh] = useState(0);
  const [theme, setTheme] = useState(
    localStorage.getItem("securechat-theme") || "dark",
  );
  const notify = () => refresh((n) => n + 1);
  const [sending, setSending] = useState<{
      name: string;
      progress: Progress;
    }>(),
    [strip, setStrip] = useState(true),
    [dragging, setDragging] = useState(false),
    [zoom, setZoom] = useState<OpenedAttachment>(),
    sendAbort = useRef<AbortController>(undefined);
  async function attach(files: FileList | File[] | null | undefined) {
    const file = files && files[0];
    if (!file || !session || sending) return;
    setError("");
    sendAbort.current = new AbortController();
    setSending({
      name: file.name,
      progress: { stage: "Preparing", fraction: 0 },
    });
    try {
      await session.sendAttachment(file, {
        stripMetadata: strip,
        signal: sendAbort.current.signal,
        onProgress: (progress) => setSending({ name: file.name, progress }),
      });
    } catch (e) {
      if ((e as Error).name !== "AbortError") setError((e as Error).message);
    } finally {
      setSending(undefined);
    }
  }
  async function authenticate(mode: "register" | "login") {
    if (
      !username.trim() ||
      (!peer.trim() && location.pathname !== "/evidence") ||
      username.trim() === peer.trim() ||
      !password
    ) {
      setError("Enter your username, a different peer, and your password.");
      return;
    }
    setBusy(true);
    setError("");
    sessionRef.current?.disconnect();
    sessionRef.current = undefined;
    try {
      const name = username.trim();
      let stored: Backup, key: CryptoKey;
      if (mode === "register") {
        const generated = await identity();
        try {
          stored = await wrap(
            name,
            password,
            generated.publicPem,
            generated.privateBytes,
          );
          key = await privateKey(generated.privateBytes);
        } finally {
          generated.privateBytes.fill(0);
        }
      } else {
        stored = await loadBackup(name);
        key = await unwrap(stored, name, password);
      }
      setBackup(stored);
      const url =
        (location.protocol === "https:" ? "wss://" : "ws://") +
        location.host +
        "/ws";
      let conn: Session;
      // eslint-disable-next-line prefer-const -- Callbacks may run before construction completes.
      conn = new Session(
        name,
        peer.trim() || "__vault_only__",
        stored.public_key_pem,
        key,
        url,
        () => {
          notify();
          if (conn?.closed && sessionRef.current === conn) setBusy(false);
        },
        async () => {
          if (mode === "register") await saveBackup(stored);
          setBusy(false);
        },
      );
      sessionRef.current = conn;
      setSession(conn);
      await conn.connect(mode, password);
      setPassword("");
    } catch (e) {
      setError((e as Error).message);
      setBusy(false);
    }
  }
  async function importBackup(file?: File) {
    if (!file) return;
    try {
      if (file.size > 32768) throw Error("Key backup is too large");
      const b = JSON.parse(await file.text()) as Backup;
      await unwrap(b, username.trim(), password);
      await saveBackup(b);
      setBackup(b);
      setError("Identity imported. You can now log in.");
    } catch (e) {
      setError("Import failed: " + (e as Error).message);
    }
  }
  async function exportEvidence() {
    try {
      download(`evidence_${session!.username}.json`, await session!.evidence());
    } catch (e) {
      setError((e as Error).message);
    }
  }
  const active = !!session?.isAuthenticated;
  if (location.pathname === "/verify")
    return (
      <div className={"app " + theme}>
        <PublicVerify />
      </div>
    );
  return (
    <div className={"app " + theme}>
      <nav>
        <a className="brand" href="/" aria-label="Secure Chat home">
          <span className="brand-mark">
            S<span>↗</span>
          </span>
          <span>
            securechat<span className="muted wordmark"> / TEAM 15</span>
          </span>
        </a>
        <div className="nav-right">
          <a href="/verify">Verify a file</a>
          {active && (
            <button
              onClick={() => {
                setEvidenceMode("list");
                history.pushState(null, "", "/evidence");
              }}
            >
              Evidence
            </button>
          )}
          <span className="pill">● END-TO-END ENCRYPTED</span>
          {active && (
            <button
              onClick={() => {
                session!.disconnect();
                sessionRef.current = undefined;
                setSession(undefined);
              }}
            >
              Disconnect ↗
            </button>
          )}
          <button
            className="icon"
            aria-label="Toggle theme"
            onClick={() => {
              const next = theme === "dark" ? "light" : "dark";
              setTheme(next);
              localStorage.setItem("securechat-theme", next);
            }}
          >
            ◐
          </button>
        </div>
      </nav>
      {!active ? (
        <main className="welcome">
          <section className="intro">
            <div className="eyebrow">PRIVATE BY DESIGN. VERIFIABLE BY YOU.</div>
            <h1>
              A conversation.
              <br />
              <span>Only yours.</span>
            </h1>
            <p>
              Your messages are encrypted on this device before they leave it.
              Signed identities and a verifiable conversation history help you
              know who you’re talking to.
            </p>
            <div className="intro-proof">
              <span>01 / SIGNED IDENTITY</span>
              <span>02 / FRESH SESSION KEYS</span>
              <span>03 / TAMPER-EVIDENT HISTORY</span>
            </div>
            <div className="visual-lock" aria-hidden="true">
              <div className="orbit one" />
              <div className="orbit two" />
              <div className="lock-symbol">↗</div>
              <span className="orbit-label">YOUR WORDS STAY BETWEEN YOU</span>
            </div>
          </section>
          <section className="login-card">
            <div className="eyebrow">YOUR SECURE SPACE</div>
            <h2>Start a conversation</h2>
            <p className="muted">
              Create an identity, or unlock one on this device.
            </p>
            <form
              onSubmit={(e) => {
                e.preventDefault();
                void authenticate("login");
              }}
            >
              <label>
                Username
                <input
                  autoComplete="username"
                  value={username}
                  onChange={(e) => setUsername(e.target.value)}
                  placeholder="Your username"
                  disabled={busy}
                />
              </label>
              <label>
                Password
                <input
                  type="password"
                  autoComplete="current-password"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  placeholder="Unlock your identity"
                  disabled={busy}
                />
              </label>
              <label>
                Peer username
                <input
                  value={peer}
                  onChange={(e) => setPeer(e.target.value)}
                  placeholder="Who are you talking to?"
                  disabled={busy}
                />
              </label>
              <button type="submit" className="primary" disabled={busy}>
                {busy ? "Securing your connection…" : "Log in →"}
              </button>
              <button
                type="button"
                className="secondary"
                disabled={busy}
                onClick={() => void authenticate("register")}
              >
                Create an identity
              </button>
            </form>
            <p role="status" className="feedback">
              {error || session?.status}
            </p>
            <div className="key-import">
              <label className="file-label">
                Import key backup
                <input
                  aria-label="Import key backup"
                  type="file"
                  accept="application/json,.json"
                  onChange={(e) => void importBackup(e.target.files?.[0])}
                />
              </label>
              <p className="muted small">
                On a new device? Enter your username and password, then import
                your wrapped backup before logging in.
              </p>
            </div>
            <p className="small privacy-note">
              ⌁ Your private key stays on this device, encrypted with your
              password.
            </p>
          </section>
        </main>
      ) : evidenceMode ? (
        <EvidencePanel
          session={session!}
          mode={evidenceMode}
          close={() => {
            setEvidenceMode(null);
            history.pushState(null, "", "/");
          }}
        />
      ) : (
        <main className={"workspace " + (wire ? "with-wire" : "")}>
          <aside className="sidebar">
            <div className="eyebrow">CONVERSATIONS / 01</div>
            <div className="contact">
              <span className="avatar">
                {session.peer.slice(0, 1).toUpperCase()}
              </span>
              <div>
                <strong>{session.peer}</strong>
                <p>{session.key ? "Secure session" : "Waiting for peer"}</p>
              </div>
              <span className="online-dot" />
            </div>
            <div className="sidebar-bottom">
              <div className="eyebrow">SIGNED IN AS</div>
              <strong>{session.username}</strong>
            </div>
          </aside>
          <section
            className={"chat" + (dragging ? " dragging" : "")}
            onDragOver={(e) => {
              if (e.dataTransfer.types.includes("Files")) {
                e.preventDefault();
                setDragging(true);
              }
            }}
            onDragLeave={() => setDragging(false)}
            onDrop={(e) => {
              e.preventDefault();
              setDragging(false);
              void attach(e.dataTransfer.files);
            }}
          >
            <header className="chat-header">
              <div>
                <div className="eyebrow">PRIVATE CONVERSATION</div>
                <h2>
                  {session.peer}
                  <span className="secure-dot">●</span>
                </h2>
              </div>
              <div className="chat-actions">
                <CallButton session={session} onError={setError} />
                <button onClick={() => setWire(!wire)} aria-pressed={wire}>
                  ⌘ Wire Log
                </button>
                <button
                  onClick={() => void exportEvidence()}
                  disabled={!session.key}
                >
                  Export Evidence ↗
                </button>
                <button
                  disabled={!session.key}
                  onClick={() => setEvidenceMode("save")}
                >
                  Save evidence
                </button>
              </div>
            </header>
            <div className="fingerprint">
              <span>PEER FINGERPRINT</span>
              <code>
                {session.fingerprint || "Waiting for signed identity…"}
              </code>
              <small>Compare out of band</small>
            </div>
            <div className="messages" aria-live="polite">
              <div className="session-divider">⌁ {session.status}</div>
              {session.messages.length === 0 && (
                <div className="empty-chat">
                  <span>⌁</span>
                  <h3>A little more private.</h3>
                  <p>
                    Once your peer connects, your devices verify each other
                    <br />
                    and derive a fresh key. The relay never receives it.
                  </p>
                </div>
              )}
              {session.messages.map((item: Message, i: number) => {
                const logged = callLogEntry(session, item, i);
                if (logged !== undefined) return logged;
                const descriptor = asDescriptor(item.message);
                if (descriptor)
                  return (
                    <AttachmentCard
                      key={i}
                      session={session}
                      descriptor={descriptor}
                      mine={item.sender === session.username}
                      onReceipt={() => setReceipt(item.receipt)}
                      onZoom={setZoom}
                    />
                  );
                return (
                  <button
                    key={i}
                    className={
                      "bubble " +
                      (item.sender === session.username ? "sent" : "received")
                    }
                    onClick={() => setReceipt(item.receipt)}
                    aria-label={"Security receipt: " + item.message}
                  >
                    <span>{item.message}</span>
                    <small>
                      {new Date(
                        item.receipt.timestamp * 1000,
                      ).toLocaleTimeString([], {
                        hour: "2-digit",
                        minute: "2-digit",
                      })}{" "}
                      · {item.receipt.chain_link === "gap" ? "⚠" : "✓✓"}
                    </small>
                  </button>
                );
              })}
            </div>
            {error && (
              <p role="alert" className="feedback">
                {error}
              </p>
            )}
            {sending && (
              <div className="att-sending" role="status">
                <div
                  role="progressbar"
                  aria-valuemin={0}
                  aria-valuemax={100}
                  aria-valuenow={Math.round(sending.progress.fraction * 100)}
                >
                  <span
                    style={{ width: `${sending.progress.fraction * 100}%` }}
                  />
                </div>
                <span>
                  {sending.name}: {stageText(sending.progress)}
                </span>
                <button onClick={() => sendAbort.current?.abort()}>
                  Cancel
                </button>
              </div>
            )}
            <form
              className="composer"
              onSubmit={(e) => {
                e.preventDefault();
                if (message.trim()) {
                  void session.sendMessage(message);
                  setMessage("");
                }
              }}
            >
              <label
                className={
                  "attach" + (!session.key || sending ? " disabled" : "")
                }
              >
                📎
                <input
                  type="file"
                  aria-label="Attach file"
                  accept="image/jpeg,image/png,image/webp,image/gif,video/mp4,video/webm,video/quicktime,.mov"
                  disabled={!session.key || !!sending}
                  onChange={(e) => {
                    void attach(e.target.files);
                    e.target.value = "";
                  }}
                />
              </label>
              <input
                aria-label="Message"
                placeholder="Write something private…"
                value={message}
                onChange={(e) => setMessage(e.target.value)}
                onPaste={(e) => {
                  if (e.clipboardData.files.length) {
                    e.preventDefault();
                    void attach(e.clipboardData.files);
                  }
                }}
                disabled={!session.key}
              />
              <button
                className="primary"
                disabled={!session.key || !message.trim()}
                aria-label="Send message"
              >
                Send ↗
              </button>
            </form>
            <label className="strip-toggle">
              <input
                type="checkbox"
                checked={strip}
                onChange={(e) => setStrip(e.target.checked)}
              />
              Remove location &amp; camera data (EXIF) from images before
              encrypting
              <small>
                {strip
                  ? "Location data is removed. Video metadata is not stripped."
                  : "Metadata, including GPS location, will be sent inside the encrypted file."}
              </small>
            </label>
            <footer>
              <span>⌁ Encrypted on your device</span>
              <button
                onClick={() =>
                  backup &&
                  download(`key_backup_${session.username}.json`, backup)
                }
              >
                Download key backup
              </button>
            </footer>
          </section>
          {wire && (
            <aside className="wire">
              <div className="eyebrow">THE NETWORK, UNFILTERED</div>
              <h3>Wire Log</h3>
              <p className="muted small">
                Actual envelopes. Passwords redacted. Message content stays
                encrypted.
              </p>
              <div className="wire-events">
                {session.wire.map((e, i) => (
                  <article key={i}>
                    <span>
                      {e.direction === "out" ? "↗ OUT" : "↙ IN"} / {e.type}
                    </span>
                    <pre>{JSON.stringify(e, null, 2)}</pre>
                  </article>
                ))}
              </div>
            </aside>
          )}
        </main>
      )}
      {session?.isAuthenticated && <CallOverlay session={session} />}
      {zoom && <Lightbox item={zoom} close={() => setZoom(undefined)} />}
      {receipt && (
        <div className="modal-backdrop" onClick={() => setReceipt(undefined)}>
          <section
            role="dialog"
            aria-modal="true"
            aria-label="Security receipt"
            className="receipt"
            onClick={(e) => e.stopPropagation()}
            onKeyDown={(e) => e.key === "Escape" && setReceipt(undefined)}
            tabIndex={-1}
          >
            <button
              className="close"
              onClick={() => setReceipt(undefined)}
              autoFocus
              aria-label="Close receipt"
            >
              ×
            </button>
            <div className="eyebrow">VERIFY, DON'T JUST TRUST</div>
            <h2>Security receipt</h2>
            <p className="receipt-verdict">
              {receipt.chain_link === "gap"
                ? "⚠ Authentic message; earlier messages missing."
                : "✓ Signed, encrypted and linked to this conversation."}
            </p>
            <dl>
              {Object.entries(receipt).map(([k, v]) => (
                <React.Fragment key={k}>
                  <dt>{k.replaceAll("_", " ")}</dt>
                  <dd>{String(v)}</dd>
                </React.Fragment>
              ))}
            </dl>
          </section>
        </div>
      )}
    </div>
  );
}
createRoot(document.getElementById("root")!).render(<App />);
