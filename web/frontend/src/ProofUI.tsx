import React, { useEffect, useState, useRef } from "react";
import { Session, type Envelope } from "./session";
import * as c from "./crypto";
import {
  encryptEvidence,
  decryptEvidence,
  vaultRequest,
} from "./evidenceVault";
import { verifyEvidence, type Verification } from "./evidenceVerify";
import { loadBackup, unwrap } from "./keystore";
import { parseDescriptor, type Descriptor } from "./attachments/descriptor";

export function downloadBytes(
  name: string,
  bytes: Uint8Array,
  type = "application/json",
) {
  const url = URL.createObjectURL(new Blob([c.raw(bytes)], { type }));
  const a = document.createElement("a");
  a.href = url;
  a.download = name;
  a.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}
export const jsonBytes = (value: unknown) =>
  c.utf8(JSON.stringify(value, null, 2) + "\n");
function Verdict({ report }: { report?: Verification }) {
  if (!report) return null;
  return (
    <section
      className={"proof-verdict " + (report.valid ? "valid" : "invalid")}
      role="status"
    >
      <h2>{report.valid ? "VALID" : "INVALID"}</h2>
      <p>
        {report.valid
          ? "Signatures and hash chains passed. Identity still requires a trusted fingerprint."
          : "Verification failed. Do not rely on this file as unaltered evidence."}
      </p>
      <ul>
        {report.failures.map((f, i) => (
          <li key={i}>
            {f.index === null ? "File" : `Message #${f.index}`}: {f.check} —{" "}
            {f.detail}
          </li>
        ))}
      </ul>
      <p>
        Receipt: {report.receipt}. JSON is the authoritative signed evidence; a
        PDF is only a companion.
      </p>
    </section>
  );
}
function AttachmentCheck({ bytes }: { bytes: Uint8Array }) {
  const [result, setResult] = useState("");
  let list: { index: number; d: Descriptor }[] = [];
  try {
    const evidence = JSON.parse(new TextDecoder().decode(bytes));
    list = (Array.isArray(evidence.records) ? evidence.records : [])
      .map((r: any, i: number) => ({ index: i + 1, d: parseDescriptor(String(r?.message)) }))
      .filter((x: any) => x.d);
  } catch {
    return null;
  }
  if (!list.length) return null;
  async function check(file?: File) {
    if (!file) return;
    if (file.size > 80 * 1024 * 1024) return setResult("File is too large to check here");
    const digest = c.hex(await c.sha(new Uint8Array(await file.arrayBuffer())));
    const hit = list.flatMap(({ index, d }) =>
      (["pt_sha256", "ct_sha256"] as const)
        .filter((k) => d[k] === digest)
        .map((k) => ({ index, d, k })),
    );
    setResult(
      hit.length
        ? hit
            .map(
              ({ index, d, k }) =>
                `MATCH: ${file.name} is the ${k === "pt_sha256" ? "original (decrypted) file" : "stored encrypted object"} recorded for message #${index} (${d.name}).`,
            )
            .join(" ")
        : `NO MATCH: ${file.name} does not equal any attachment recorded in this evidence.`,
    );
  }
  return (
    <section className="proof-card" aria-label="Attachments in this evidence">
      <h3>Attachments recorded in this evidence</h3>
      <ul>
        {list.map(({ index, d }) => (
          <li key={index}>
            Message #{index}: {d.name} ({d.mime}, {d.size} bytes) — SHA-256{" "}
            <code>{d.pt_sha256}</code>
          </li>
        ))}
      </ul>
      <label>
        Check a file against these recorded hashes (nothing is uploaded)
        <input
          type="file"
          aria-label="Attachment file to check"
          onChange={(e) => void check(e.target.files?.[0])}
        />
      </label>
      <p role="status">{result}</p>
    </section>
  );
}
export function PublicVerify() {
  const revision = useRef(0);
  const reset = () => {
    revision.current++;
    setReport(undefined);
  };
  const [bytes, setBytes] = useState<Uint8Array>(),
    [receipt, setReceipt] = useState<Envelope>(),
    [key, setKey] = useState(""),
    [pin, setPin] = useState(""),
    [report, setReport] = useState<Verification>(),
    [error, setError] = useState(""),
    [name, setName] = useState("");
  async function evidence(file?: File) {
    if (!file) return;
    reset();
    const request = revision.current;
    setBytes(undefined);
    setName("");
    try {
      if (file.size > 8 * 1024 * 1024)
        throw Error("Maximum evidence size is 8 MiB");
      const loaded = new Uint8Array(await file.arrayBuffer());
      if (request !== revision.current) return;
      setBytes(loaded);
      setName(file.name);
      setReport(undefined);
      setError("");
    } catch (e) {
      setError((e as Error).message);
    }
  }
  async function verify() {
    try {
      if (!bytes) throw Error("Choose an evidence JSON file");
      const request = revision.current;
      const result = await verifyEvidence(
        bytes,
        receipt,
        key,
        pin ? [pin] : [],
      );
      if (request !== revision.current) return;
      setReport(result);
      setError("");
    } catch (e) {
      setError((e as Error).message);
    }
  }
  return (
    <main className="proof-page">
      <div className="eyebrow">OFFLINE VERIFICATION / NO LOGIN</div>
      <h1>Verify evidence</h1>
      <p>
        Files stay on your device. Verification makes no network requests. Trust
        a participant fingerprint and the timestamp public key through an
        independent source.
      </p>
      <section
        className="proof-card"
        onDragOver={(e) => e.preventDefault()}
        onDrop={(e) => {
          e.preventDefault();
          void evidence(e.dataTransfer.files[0]);
        }}
      >
        <label>
          Evidence JSON file — or drop it here
          <input
            type="file"
            aria-label="Evidence JSON file"
            accept=".json,application/json"
            onChange={(e) => void evidence(e.target.files?.[0])}
          />
        </label>
        {name && <p>{name}</p>}
        <label>
          Optional receipt JSON
          <input
            type="file"
            aria-label="Receipt JSON file"
            accept=".json"
            onChange={async (e) => {
              try {
                reset();
                const request = revision.current;
                setReceipt(undefined);
                const parsed = JSON.parse(await e.target.files![0].text());
                if (request === revision.current) setReceipt(parsed);
              } catch {
                setError("Invalid receipt JSON");
              }
            }}
          />
        </label>
        <label>
          Trusted TSA public key (PEM)
          <textarea
            value={key}
            onChange={(e) => {
              setKey(e.target.value);
              reset();
            }}
            placeholder="-----BEGIN PUBLIC KEY-----"
          />
        </label>
        <label>
          Optional trusted participant fingerprint
          <input
            value={pin}
            onChange={(e) => {
              setPin(e.target.value);
              reset();
            }}
            placeholder="AAAA BBBB CCCC DDDD"
          />
        </label>
        <button className="primary" onClick={() => void verify()}>
          Verify locally
        </button>
        <button
          onClick={() => {
            setReceipt(undefined);
            setKey("");
            reset();
          }}
        >
          Clear optional receipt
        </button>
        <p role="alert">{error}</p>
        <Verdict report={report} />
        {report && bytes && <AttachmentCheck bytes={bytes} />}
        {report && bytes && (
          <button
            onClick={async () => {
              const { createReport } = await import("./pdfReport");
              downloadBytes(
                "evidence-report.pdf",
                await createReport(bytes, report, receipt),
                "application/pdf",
              );
            }}
          >
            Download companion PDF
          </button>
        )}
      </section>
      <a href="/">Back to Secure Chat</a>
    </main>
  );
}
export function EvidencePanel({
  session,
  mode,
  close,
}: {
  session: Session;
  mode: "save" | "list";
  close: () => void;
}) {
  const [rows, setRows] = useState<Envelope[]>([]),
    [password, setPassword] = useState(""),
    [title, setTitle] = useState("Conversation evidence"),
    [error, setError] = useState(""),
    [busy, setBusy] = useState(false),
    [report, setReport] = useState<Verification>(),
    [selected, setSelected] = useState<{
      bytes: Uint8Array;
      receipt: Envelope;
    }>();
  async function refresh() {
    try {
      setRows(await vaultRequest(session.apiToken));
    } catch (e) {
      setError((e as Error).message);
    }
  }
  useEffect(() => {
    void refresh();
  }, []);
  async function save() {
    setBusy(true);
    setError("");
    try {
      await unwrap(
        await loadBackup(session.username),
        session.username,
        password,
      );
      const data = await session.evidence(2),
        bytes = jsonBytes(data),
        encrypted = await encryptEvidence(bytes, password);
      const row = await vaultRequest(session.apiToken, "", {
        method: "POST",
        body: JSON.stringify({
          title,
          file_sha256: encrypted.file_sha256,
          ciphertext_b64: c.b64(c.utf8(JSON.stringify(encrypted))),
          format_version: 2,
          total: data.records.length,
          envelope_hashes: data.records.map((r: Envelope) => r.envelope_sha256),
        }),
      });
      setSelected({ bytes, receipt: row.timestamp_receipt });
      const info = await fetch("/api/timestamp-key").then((r) => r.json());
      setReport(
        await verifyEvidence(bytes, row.timestamp_receipt, info.public_key_pem),
      );
      setError(
        "Saved encrypted evidence. Download the exact JSON and its receipt below.",
      );
      await refresh();
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setPassword("");
      setBusy(false);
    }
  }
  async function open(row: Envelope, download = false) {
    setBusy(true);
    try {
      const bundle = await vaultRequest(session.apiToken, "/" + row.id),
        packageJson = JSON.parse(
          new TextDecoder().decode(c.un64(bundle.ciphertext_b64)),
        ),
        bytes = await decryptEvidence(packageJson, password);
      const key = await fetch("/api/timestamp-key").then((r) => r.json());
      const result = await verifyEvidence(
        bytes,
        bundle.timestamp_receipt,
        key.public_key_pem,
      );
      setSelected({ bytes, receipt: bundle.timestamp_receipt });
      setReport(result);
      setError(
        result.receipt === "valid"
          ? "Receipt signature matches this server’s current key; see the full verdict below. Pin the key independently for third-party use."
          : "Receipt is INVALID or could not be verified with the current server key. See the full verdict below.",
      );
      if (download) downloadBytes("evidence_" + row.id + ".json", bytes);
    } catch (e) {
      setError("Cannot unlock/verify: " + (e as Error).message);
    } finally {
      setBusy(false);
    }
  }
  return (
    <main className="proof-page">
      <button onClick={close}>← Back to chat</button>
      <div className="eyebrow">PRIVATE EVIDENCE VAULT</div>
      <h1>Evidence</h1>
      <p>
        Evidence is encrypted on this device before upload. The relay sees
        titles, hashes, sizes and matching traffic metadata, but cannot read the
        saved conversation.
      </p>
      <section className="proof-card">
        <label>
          Vault password
          <input
            type="password"
            aria-label="Vault password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            autoComplete="current-password"
          />
        </label>
        {mode === "save" && (
          <>
            <label>
              Evidence title
              <input
                aria-label="Evidence title"
                maxLength={120}
                value={title}
                onChange={(e) => setTitle(e.target.value)}
              />
            </label>
            <button
              className="primary"
              disabled={busy || !password}
              onClick={() => void save()}
            >
              Encrypt and save
            </button>
          </>
        )}
        <p role="status">{error}</p>
        <button onClick={() => void refresh()}>Refresh evidence list</button>
      </section>
      <div className="vault-list">
        {rows.length === 0 && <p>No saved evidence yet.</p>}
        {rows.map((row) => (
          <article className="proof-card" key={row.id}>
            <h2>{row.title}</h2>
            <p>
              {new Date(row.created_at * 1000).toISOString()} · {row.size_bytes}{" "}
              encrypted bytes
            </p>
            <code className="file-hash">{row.file_sha256}</code>
            <p>
              Receipt: unverified until unlocked. Corroboration claim:{" "}
              {row.timestamp_receipt.corroborated} /{" "}
              {row.timestamp_receipt.total}
            </p>
            <button
              disabled={busy || !password}
              onClick={() => void open(row, true)}
            >
              Download JSON
            </button>
            <button disabled={busy || !password} onClick={() => void open(row)}>
              Verify saved evidence
            </button>
            <button
              onClick={async () => {
                try {
                  await vaultRequest(session.apiToken, "/" + row.id, {
                    method: "DELETE",
                  });
                  setSelected(undefined);
                  setReport(undefined);
                  await refresh();
                } catch (e) {
                  setError((e as Error).message);
                }
              }}
            >
              Delete evidence
            </button>
          </article>
        ))}
      </div>
      <Verdict report={report} />
      {selected && (
        <section className="proof-card">
          <h2>Selected evidence</h2>
          <button
            onClick={() => downloadBytes("evidence.json", selected.bytes)}
          >
            Download exact signed JSON
          </button>
          <button
            onClick={() =>
              downloadBytes("receipt.json", jsonBytes(selected.receipt))
            }
          >
            Download timestamp receipt
          </button>
          <button
            onClick={async () => {
              const info = await fetch("/api/timestamp-key").then((r) =>
                r.json(),
              );
              downloadBytes(
                "tsa-public.pem",
                c.utf8(info.public_key_pem),
                "text/plain",
              );
            }}
          >
            Download TSA public key
          </button>
          <button
            onClick={async () => {
              const result = report || (await verifyEvidence(selected.bytes));
              const { createReport } = await import("./pdfReport");
              downloadBytes(
                "evidence-report.pdf",
                await createReport(selected.bytes, result, selected.receipt),
                "application/pdf",
              );
            }}
          >
            Download companion PDF
          </button>
        </section>
      )}
      <p>
        Keep the signed JSON, receipt, and independently trusted public key
        together. This is technical integrity evidence, not legal certification.
      </p>
    </main>
  );
}
