import * as c from "./crypto";
import { sniff, stripMetadata, sanitizeFilename, type Kind } from "./attachments/media";
import { encryptFile, decryptFile, AttachmentError, type FileSecrets } from "./attachments/fileCrypto";
import { encodeDescriptor, type Descriptor } from "./attachments/descriptor";
import { makeThumbnail } from "./attachments/thumbnail";
import { api, putObject, getObject, type Presigned } from "./attachments/transfer";
export type Envelope = Record<string, any>;
export interface Message {
  sender: string;
  message: string;
  receipt: Envelope;
}
export interface AttachmentLimits {
  image_max: number;
  video_max: number;
  user_quota: number;
  retention_seconds: number;
}
export interface OpenedAttachment {
  url: string;
  mime: string;
  name: string;
  size: number;
}
export type Stage = "Preparing" | "Encrypting" | "Uploading" | "Sending" | "Downloading" | "Decrypting" | "Verifying";
export interface Progress {
  stage: Stage;
  fraction: number;
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
  opened = new Map<string, OpenedAttachment>();
  limits?: AttachmentLimits;
  private epoch = 0;
  private stopped = false;
  private reconnecting = false;
  private retries = 0;
  private retryTimer?: ReturnType<typeof setTimeout>;
  private openTimer?: ReturnType<typeof setTimeout>;
  constructor(
    public username: string,
    public peer: string,
    public ownPem: string,
    private privateKey: CryptoKey,
    private url: string,
    private changed: () => void,
    private authenticated: () => Promise<void> = async () => {},
  ) {
    this.secureTransport = url.startsWith("wss:");
    this.socket = this.openSocket();
  }
  private clearSession() {
    this.epoch++;
    this.apiToken = "";
    this.key = undefined;
    this.pending = undefined;
    this.pendingSig = "";
    this.initiated = false;
    this.peerOnline = false;
    this.deferred = [];
    this.seen.clear();
    this.rejectedNonces.clear();
    this.handshake = undefined;
    this.outHead = this.inHead = "";
    this.outSeq = this.inSeq = 1;
  }
  disconnect() {
    this.stopped = true;
    this.reconnecting = false;
    clearTimeout(this.retryTimer);
    clearTimeout(this.openTimer);
    this.clearSession();
    this.isAuthenticated = false;
    for (const o of this.opened.values()) URL.revokeObjectURL(o.url);
    this.opened.clear();
    this.socket.close();
  }
  private openSocket() {
    const socket = new WebSocket(this.url);
    socket.onmessage = (e) => {
      if (this.socket === socket && !this.closed)
        this.enqueue(async () => this.receive(JSON.parse(e.data)));
    };
    socket.onopen = () => {
      if (this.socket !== socket || this.stopped) return;
      clearTimeout(this.openTimer);
      this.closed = false;
      if (this.reconnecting) {
        this.reconnecting = false;
        this.retries = 0;
        this.status =
          "Connection restored — log in again for a fresh signed handshake.";
        this.changed();
      }
    };
    socket.onclose = () => {
      if (this.socket !== socket) return;
      clearTimeout(this.openTimer);
      const retry =
        !this.stopped && (this.isAuthenticated || this.reconnecting);
      this.closed = true;
      this.clearSession();
      this.isAuthenticated = false;
      if (retry) this.retry();
      this.changed();
    };
    socket.onerror = () => {
      if (!this.reconnecting)
        this.status = "Connection failed — log in to retry";
      this.changed();
    };
    return socket;
  }
  private retry() {
    if (this.retries >= 8) {
      this.reconnecting = false;
      this.status =
        "Could not reconnect. Wait for the service, then log in again.";
      return;
    }
    this.reconnecting = true;
    this.status =
      "Reconnecting… Session keys discarded. Login will be required.";
    const delay = Math.min(1000 * 2 ** this.retries++, 30000);
    this.retryTimer = setTimeout(() => {
      if (this.stopped) return;
      this.socket = this.openSocket();
      this.openTimer = setTimeout(() => this.socket.close(), 20000);
    }, delay);
  }
  enqueue(work: () => Promise<unknown>) {
    const epoch = this.epoch;
    this.chain = this.chain
      .then(() => (epoch === this.epoch && !this.stopped ? work() : undefined))
      .catch((e) => {
        if (epoch !== this.epoch) return;
        this.status = String(e.message || e);
        this.changed();
      });
    return this.chain;
  }
  async connect(mode: "register" | "login", password: string) {
    await new Promise<void>((resolve, reject) => {
      if (this.socket.readyState === WebSocket.OPEN) {
        resolve();
        return;
      }
      this.socket.addEventListener("open", () => resolve(), { once: true });
      this.socket.addEventListener(
        "error",
        () => reject(Error("Cannot connect")),
        { once: true },
      );
      this.socket.addEventListener(
        "close",
        () => reject(Error("Connection closed before login")),
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
        this.disconnect();
        throw Error(e.reason);
      }
      this.apiToken = e.api_token || "";
      const epoch = this.epoch;
      await this.authenticated();
      if (epoch !== this.epoch) return;
      this.isAuthenticated = true;
      this.status = "Authenticated — waiting for peer";
      this.send({ type: "get_pubkey", username: this.username });
      this.send({ type: "get_pubkey", username: this.peer });
    } else if (e.type === "pubkey_result" && e.username === this.username) {
      if (!e.success || e.public_key !== this.ownPem) {
        this.disconnect();
        throw Error(
          "Local identity does not match this account. Import the correct key backup.",
        );
      }
    } else if (e.type === "user_left" && e.username === this.peer) {
      this.clearSession();
      this.status = "Peer disconnected — waiting for a fresh signed handshake";
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
    const epoch = this.epoch;
    if (e.type === "handshake_response" && !this.pending) return;
    const pub = c.un64(e.pubkey),
      sig = c.un64(e.handshake_sig);
    if (!(await c.verify(this.peerKey!, pub, sig))) {
      if (epoch !== this.epoch) return;
      this.pending = undefined;
      this.initiated = false;
      this.reject("handshake_aborted", "signature_failed", e);
      return;
    }
    if (epoch !== this.epoch) return;
    if (e.type === "handshake_init") {
      const own = await c.ephemeral(),
        ownSig = c.b64(await c.sign(this.privateKey, own.pub));
      const key = await c.shared(own, pub);
      if (epoch !== this.epoch) return;
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
        epoch,
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
        epoch,
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
    epoch = this.epoch,
  ) {
    const [outHead, inHead] = await Promise.all([
      c.genesis(ip, rp, this.username),
      c.genesis(ip, rp, this.peer),
    ]);
    if (epoch !== this.epoch || this.stopped || this.closed) return;
    this.key = key;
    this.handshake = {
      initiator,
      responder,
      ecdh_public_keys: { initiator: c.b64(ip), responder: c.b64(rp) },
      handshake_signatures: { initiator: is, responder: rs },
    };
    this.outHead = outHead;
    this.inHead = inHead;
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
    const epoch = this.epoch;
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
    if (epoch !== this.epoch) return;
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
    if (epoch !== this.epoch) return;
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
    const epoch = this.epoch;
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
      if (epoch !== this.epoch)
        throw Error("Connection changed; message was not sent");
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
  private wireNote(direction: "out" | "in", type: string, fields: Envelope) {
    this.wire.push({ direction, type, ...fields });
    this.wire = this.wire.slice(-200);
    this.changed();
  }
  /** Encrypt in the browser, upload ciphertext only, then send the key in a normal E2E message. */
  async sendAttachment(
    file: File,
    opts: {
      stripMetadata: boolean;
      onProgress?: (p: Progress) => void;
      signal?: AbortSignal;
    },
  ) {
    const say = (stage: Stage, fraction = 0) => opts.onProgress?.({ stage, fraction });
    if (!this.key || !this.apiToken) throw Error("Wait for a verified handshake");
    const epoch = this.epoch;
    say("Preparing");
    this.limits ??= await api<AttachmentLimits>(this.apiToken, "GET", "/api/attachments/config");
    // Reject before reading whole oversized files into memory.
    if (file.size === 0) throw Error("That file is empty");
    if (file.size > this.limits.video_max) throw Error(`File exceeds the ${this.limits.video_max / 2 ** 20} MiB limit`);
    let bytes = new Uint8Array(await file.arrayBuffer());
    const type = sniff(bytes);
    if (!type) throw Error("Unsupported file type. Allowed: JPEG, PNG, WebP, GIF, MP4, WebM");
    const max = type.kind === "image" ? this.limits.image_max : this.limits.video_max;
    if (bytes.length > max) throw Error(`${type.kind === "image" ? "Images" : "Videos"} are limited to ${max / 2 ** 20} MiB`);
    const stripped = opts.stripMetadata && type.kind === "image";
    if (stripped) bytes = stripMetadata(bytes, type.mime) as Uint8Array<ArrayBuffer>;
    const thumb = await makeThumbnail(bytes, type.mime, type.kind);
    const { ciphertext, secrets } = await encryptFile(bytes, {
      signal: opts.signal,
      onProgress: (d, t) => say("Encrypting", d / t),
    });
    if (epoch !== this.epoch) throw Error("Connection changed; attachment was not sent");
    const init = await api<{ upload: Presigned }>(this.apiToken, "POST", "/api/attachments", {
      id: secrets.id,
      recipient: this.peer,
      kind: type.kind,
      ciphertext_size: secrets.ct_size,
      ciphertext_sha256: secrets.ct_sha256,
    });
    this.wireNote("out", "attachment_upload", {
      note: "Only ciphertext was uploaded (HTTPS PUT straight to object storage)",
      ciphertext_sha256: secrets.ct_sha256,
      ciphertext_size: secrets.ct_size,
      storage_host: new URL(init.upload.url, location.href).host,
    });
    try {
      await putObject(init.upload, ciphertext, (l, t) => say("Uploading", t ? l / t : l / secrets.ct_size), opts.signal);
      say("Uploading", 1);
      await api(this.apiToken, "POST", `/api/attachments/${secrets.id}/finalize`);
    } catch (e) {
      // Best effort: free the quota of a cancelled or failed upload.
      api(this.apiToken, "DELETE", `/api/attachments/${secrets.id}`).catch(() => {});
      throw e;
    }
    say("Sending");
    const descriptor: Descriptor = {
      v: 1,
      ...secrets,
      name: sanitizeFilename(file.name, type.ext),
      mime: type.mime,
      kind: type.kind as Kind,
      ...(thumb ? { thumb: c.b64(thumb) } : {}),
      ...(stripped ? { stripped: true } : {}),
    };
    await this.sendMessage(encodeDescriptor(descriptor));
    this.opened.set(descriptor.id, {
      url: URL.createObjectURL(new Blob([bytes as BlobPart], { type: type.mime })),
      mime: type.mime,
      name: descriptor.name,
      size: bytes.length,
    });
    this.changed();
  }
  /** Download, verify the ciphertext hash, decrypt, verify the plaintext hash and type. */
  async openAttachment(
    d: Descriptor,
    onProgress?: (p: Progress) => void,
    signal?: AbortSignal,
  ): Promise<OpenedAttachment> {
    const have = this.opened.get(d.id);
    if (have) return have;
    if (!this.apiToken) throw Error("Log in to download attachments");
    const say = (stage: Stage, fraction = 0) => onProgress?.({ stage, fraction });
    say("Downloading");
    const info = await api<{ url: string; ciphertext_sha256: string; ciphertext_size: number }>(
      this.apiToken, "GET", `/api/attachments/${d.id}/download`,
    );
    this.wireNote("in", "attachment_download", {
      note: "Downloaded ciphertext only; decrypted locally with the key from the signed message",
      ciphertext_sha256: info.ciphertext_sha256,
      ciphertext_size: info.ciphertext_size,
    });
    const ciphertext = await getObject(info.url, (l, t) => say("Downloading", t ? l / t : l / d.ct_size), signal);
    say("Verifying");
    const secrets: FileSecrets = { id: d.id, key: d.key, chunk: d.chunk, size: d.size, ct_size: d.ct_size, ct_sha256: d.ct_sha256, pt_sha256: d.pt_sha256 };
    let plain: Uint8Array;
    try {
      plain = await decryptFile(ciphertext, secrets, { signal, onProgress: (n, t) => say("Decrypting", n / t) });
    } catch (e) {
      if (e instanceof AttachmentError) {
        this.wireNote("in", "attachment_rejected", { reason: e.code, note: e.message });
        this.send({ type: "security_alert", alert: "attachment_rejected", reason: e.code, peer: this.peer });
      }
      throw e;
    }
    // Never trust the sender's declared type: re-check the decrypted bytes.
    const type = sniff(plain);
    if (!type || type.mime !== d.mime)
      throw new AttachmentError("type", "Attachment rejected: content does not match its declared type");
    const opened = {
      url: URL.createObjectURL(new Blob([plain as BlobPart], { type: type.mime })),
      mime: type.mime,
      name: sanitizeFilename(d.name, type.ext),
      size: plain.length,
    };
    this.opened.set(d.id, opened);
    this.changed();
    return opened;
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
