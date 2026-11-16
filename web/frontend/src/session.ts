import * as c from "./crypto";
export type Envelope = Record<string, any>;
export interface Message {
  sender: string;
  message: string;
  receipt: Envelope;
}
export class Session {
  socket: WebSocket;
  isAuthenticated = false;
  apiToken = "";
  secureTransport = false;
  key?: CryptoKey;
  peerKey?: CryptoKey;
  peerPem = "";
  fingerprint = "";
  status = "Connecting";
  messages: Message[] = [];
  wire: Envelope[] = [];
  transcript: Envelope[] = [];
  rejected: Envelope[] = [];
  outHead = "";
  inHead = "";
  outSeq = 1;
  inSeq = 1;
  startedAt = 0;
  handshake?: Envelope;
  pending?: c.Ephemeral;
  pendingSig = "";
  initiated = false;
  peerOnline = false;
  deferred: Envelope[] = [];
  seen = new Map<string, number>();
  rejectedNonces = new Set<string>();
  chain: Promise<unknown> = Promise.resolve();
  closed = false;
  constructor(
    public username: string,
    public peer: string,
    public ownPem: string,
    private privateKey: CryptoKey,
    url: string,
    private changed: () => void,
    private authenticated: () => Promise<void> = async () => {},
  ) {
    this.secureTransport = url.startsWith("wss:");
    this.socket = new WebSocket(url);
    this.socket.onmessage = (e) =>
      this.enqueue(async () => this.receive(JSON.parse(e.data)));
    this.socket.onclose = () => {
      this.closed = true;
      this.apiToken = "";
      this.key = undefined;
      this.pending = undefined;
      if (this.isAuthenticated)
        this.status = "Disconnected — reconnect to start a fresh session";
      this.changed();
    };
    this.socket.onerror = () => {
      this.status = "Connection failed";
      this.changed();
    };
  }
  enqueue(work: () => Promise<unknown>) {
    this.chain = this.chain.then(work).catch((e) => {
      this.status = String(e.message || e);
      this.changed();
    });
    return this.chain;
  }
  async connect(mode: "register" | "login", password: string) {
    await new Promise<void>((resolve, reject) => {
      this.socket.onopen = () => resolve();
      this.socket.addEventListener(
        "error",
        () => reject(Error("Cannot connect")),
        { once: true },
      );
    });
    this.send({
      type: mode,
      username: this.username,
      password,
      ...(mode === "register" ? { public_key: this.ownPem } : {}),
    });
  }
  send(envelope: Envelope) {
    if (this.socket.readyState !== WebSocket.OPEN) throw Error("Disconnected");
    this.wire.push({
      direction: "out",
      ...envelope,
      ...("password" in envelope
        ? {
            password: this.secureTransport
              ? "[redacted — WSS transport]"
              : "[redacted — local WS; HTTPS required on networks]",
          }
        : {}),
    });
    this.wire = this.wire.slice(-200);
    this.socket.send(JSON.stringify(envelope));
    this.changed();
  }
  async receive(e: Envelope) {
    this.wire.push({
      direction: "in",
      ...e,
      ...(e.api_token ? { api_token: "[redacted]" } : {}),
    });
    this.wire = this.wire.slice(-200);
    if (e.type === "register_result" || e.type === "login_result") {
      if (!e.success) {
        this.status = e.reason;
        this.socket.close();
        throw Error(e.reason);
      }
      this.apiToken = e.api_token || "";
      await this.authenticated();
      this.isAuthenticated = true;
      this.status = "Authenticated — waiting for peer";
      this.send({ type: "get_pubkey", username: this.username });
      this.send({ type: "get_pubkey", username: this.peer });
    } else if (e.type === "pubkey_result" && e.username === this.username) {
      if (!e.success || e.public_key !== this.ownPem) {
        this.socket.close();
        throw Error(
          "Local identity does not match this account. Import the correct key backup.",
        );
      }
    } else if (e.type === "roster" || e.type === "user_joined") {
      if (e.users?.includes(this.peer) || e.username === this.peer) {
        this.peerOnline = true;
        this.send({ type: "get_pubkey", username: this.peer });
        await this.maybeInitiate();
      }
    } else if (
      e.type === "pubkey_result" &&
      e.username === this.peer &&
      e.success
    ) {
      this.peerPem = e.public_key;
      this.peerKey = await c.publicKey(this.peerPem);
      this.fingerprint = await c.fingerprint(this.peerPem);
      const waiting = this.deferred;
      this.deferred = [];
      for (const item of waiting) await this.receiveHandshake(item);
      await this.maybeInitiate();
    } else if (
      (e.type === "handshake_init" || e.type === "handshake_response") &&
      e.from === this.peer
    ) {
      if (!this.peerKey) {
        this.deferred.push(e);
        this.send({ type: "get_pubkey", username: this.peer });
      } else await this.receiveHandshake(e);
    } else if (e.type === "chat" && e.from === this.peer)
      await this.receiveChat(e);
    else if (e.type === "error") this.status = e.reason;
    this.changed();
  }
  async maybeInitiate() {
    if (
      !this.peerOnline ||
      !this.peerKey ||
      this.initiated ||
      this.key ||
      c.compare(this.username, this.peer) >= 0
    )
      return;
    this.initiated = true;
    this.pending = await c.ephemeral();
    this.pendingSig = c.b64(await c.sign(this.privateKey, this.pending.pub));
    this.status = "Verifying signed X25519 handshake";
    this.send({
      type: "handshake_init",
      from: this.username,
      to: this.peer,
      pubkey: c.b64(this.pending.pub),
      handshake_sig: this.pendingSig,
    });
  }
  async receiveHandshake(e: Envelope) {
    if (e.type === "handshake_response" && !this.pending) return;
    const pub = c.un64(e.pubkey),
      sig = c.un64(e.handshake_sig);
    if (!(await c.verify(this.peerKey!, pub, sig))) {
      this.pending = undefined;
      this.initiated = false;
      this.reject("handshake_aborted", "signature_failed", e);
      return;
    }
    if (e.type === "handshake_init") {
      const own = await c.ephemeral(),
        ownSig = c.b64(await c.sign(this.privateKey, own.pub));
      const key = await c.shared(own, pub);
      this.send({
        type: "handshake_response",
        from: this.username,
        to: this.peer,
        pubkey: c.b64(own.pub),
        handshake_sig: ownSig,
      });
      await this.finish(
        key,
        this.peer,
        this.username,
        pub,
        own.pub,
        e.handshake_sig,
        ownSig,
      );
    } else {
      const own = this.pending!;
      this.pending = undefined;
      const key = await c.shared(own, pub);
      await this.finish(
        key,
        this.username,
        this.peer,
        own.pub,
        pub,
        this.pendingSig,
        e.handshake_sig,
      );
    }
  }
  async finish(
    key: CryptoKey,
    initiator: string,
    responder: string,
    ip: Uint8Array,
    rp: Uint8Array,
    is: string,
    rs: string,
  ) {
    this.key = key;
    this.handshake = {
      initiator,
      responder,
      ecdh_public_keys: { initiator: c.b64(ip), responder: c.b64(rp) },
      handshake_signatures: { initiator: is, responder: rs },
    };
    this.outHead = await c.genesis(ip, rp, this.username);
    this.inHead = await c.genesis(ip, rp, this.peer);
    this.outSeq = this.inSeq = 1;
    this.seen.clear();
    this.rejectedNonces.clear();
    this.transcript = [];
    this.startedAt = Math.floor(Date.now() / 1000);
    this.status = "Secure session established";
  }
  reject(kind: string, reason: string, e: Envelope, missing = 0) {
    this.rejected.push({
      at: Math.floor(Date.now() / 1000),
      kind,
      sender: e.from || this.peer,
      reason,
      detail: reason,
      ...(missing ? { missing } : {}),
    });
    this.status = `Security warning: ${reason}`;
    if (
      kind === "message_rejected" &&
      [
        "decryption_failed",
        "malformed",
        "signature_failed",
        "unknown_peer_key",
        "stale_timestamp",
      ].includes(reason)
    )
      this.rejectedNonces.add(e.nonce || "");
    this.send({ type: "security_alert", alert: kind, reason, peer: this.peer });
  }
  async receiveChat(e: Envelope) {
    if (!this.key) {
      this.reject("message_rejected", "no_session_key", e);
      return;
    }
    let inner: Envelope;
    try {
      inner = await c.decrypt(this.key, e as any);
    } catch {
      this.reject("message_rejected", "decryption_failed", e);
      return;
    }
    if (
      !inner ||
      typeof inner.message !== "string" ||
      !Number.isSafeInteger(inner.timestamp) ||
      !Number.isSafeInteger(inner.seq) ||
      typeof inner.prev_hash !== "string" ||
      typeof inner.signature !== "string"
    ) {
      this.reject("message_rejected", "malformed", e);
      return;
    }
    const rec = c.record(
      this.peer,
      this.username,
      inner.seq,
      inner.timestamp,
      inner.message,
      inner.prev_hash,
    );
    try {
      if (
        !this.peerKey ||
        !(await c.verify(
          this.peerKey,
          c.utf8(c.canonical(rec)),
          c.un64(inner.signature),
        ))
      ) {
        this.reject("message_rejected", "signature_failed", e);
        return;
      }
    } catch {
      this.reject("message_rejected", "signature_failed", e);
      return;
    }
    const now = Date.now() / 1000;
    if (inner.timestamp < now - 30 || inner.timestamp > now + 5) {
      this.reject("message_rejected", "stale_timestamp", e);
      return;
    }
    for (const [nonce, at] of this.seen)
      if (now - at > 35) this.seen.delete(nonce);
    if (this.seen.has(e.nonce)) {
      this.reject("message_rejected", "replay_duplicate", e);
      return;
    }
    this.seen.set(e.nonce, now);
    if (
      inner.seq < 1 ||
      inner.seq < this.inSeq ||
      (inner.seq === this.inSeq && inner.prev_hash !== this.inHead)
    ) {
      this.reject("message_rejected", "chain_broken", e);
      return;
    }
    const gap = inner.seq > this.inSeq,
      missing = inner.seq - this.inSeq,
      explained = Math.min(missing, this.rejectedNonces.size);
    if (gap) this.reject("chain_warning", "chain_gap", e, missing);
    this.inHead = await c.hash(rec);
    this.inSeq = inner.seq + 1;
    this.rejectedNonces.clear();
    this.transcript.push({
      ...rec,
      record_hash: this.inHead,
      signature: inner.signature,
      envelope_sha256: await c.hash(e),
    });
    this.messages.push({
      sender: this.peer,
      message: inner.message,
      receipt: {
        direction: "received",
        sender: this.peer,
        sender_fingerprint: this.fingerprint,
        timestamp: inner.timestamp,
        seq: inner.seq,
        prev_hash: inner.prev_hash,
        record_hash: this.inHead,
        nonce: e.nonce,
        chain_link: gap ? "gap" : "ok",
        missing,
        explained,
      },
    });
  }
  async sendMessage(message: string) {
    return this.enqueue(async () => {
      if (!this.key) throw Error("Wait for a verified handshake");
      const rec = c.record(
        this.username,
        this.peer,
        this.outSeq,
        Math.floor(Date.now() / 1000),
        message,
        this.outHead,
      );
      const signature = c.b64(
        await c.sign(this.privateKey, c.utf8(c.canonical(rec))),
      );
      const box = await c.encrypt(this.key, {
        message,
        timestamp: rec.timestamp,
        seq: rec.seq,
        prev_hash: rec.prev_hash,
        signature,
      });
      const envelope = {
        type: "chat",
        from: this.username,
        to: this.peer,
        ...box,
      };
      this.send(envelope);
      this.outHead = await c.hash(rec);
      this.outSeq++;
      this.transcript.push({
        ...rec,
        record_hash: this.outHead,
        signature,
        envelope_sha256: await c.hash(envelope),
      });
      this.messages.push({
        sender: this.username,
        message,
        receipt: {
          direction: "sent",
          sender: this.username,
          timestamp: rec.timestamp,
          seq: rec.seq,
          prev_hash: rec.prev_hash,
          record_hash: this.outHead,
          nonce: box.nonce,
          chain_link: "ok",
        },
      });
      this.changed();
    });
  }
  async evidence(formatVersion = 2) {
    await this.chain;
    if (!this.handshake || !this.key)
      throw Error("Complete the handshake first");
    const now = Math.floor(Date.now() / 1000);
    const body: Envelope = {
      format:
        formatVersion === 2
          ? "securechat-evidence/v2"
          : "securechat-evidence/v1",
      exported_by: this.username,
      exported_at: now,
      session: { ...this.handshake, started_at: this.startedAt, ended_at: now },
      participants: {
        [this.username]: {
          public_key_pem: this.ownPem,
          fingerprint: await c.fingerprint(this.ownPem),
        },
        [this.peer]: {
          public_key_pem: this.peerPem,
          fingerprint: this.fingerprint,
        },
      },
      records: this.transcript.map((row) => {
        const record = { ...row };
        if (formatVersion === 1) delete record.envelope_sha256;
        return record;
      }),
      chain_heads: { [this.username]: this.outHead, [this.peer]: this.inHead },
      rejected_events: [...this.rejected],
    };
    if (formatVersion === 2) body.format_version = 2;
    body.exporter_signature = c.b64(
      await c.sign(this.privateKey, c.utf8(c.canonical(body))),
    );
    return body;
  }
}
