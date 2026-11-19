import React, { useState, useRef } from "react";
import { type Envelope } from "./session";
import * as c from "./crypto";
import { verifyEvidence, type Verification } from "./evidenceVerify";
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
      .map((r: Envelope | null, i: number) => ({
        index: i + 1,
        d: parseDescriptor(String(r?.message)),
      }))
      .filter(
        (x: {
          index: number;
          d: Descriptor | null;
        }): x is { index: number; d: Descriptor } => !!x.d,
      );
  } catch {
    return null;
  }
  if (!list.length) return null;
  async function check(file?: File) {
    if (!file) return;
    if (file.size > 80 * 1024 * 1024)
      return setResult("File is too large to check here");
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
      const result = await verifyEvidence(bytes);
      if (request !== revision.current) return;
      setReport(result);
      setError("");
    } catch (e) {
      setError((e as Error).message);
    }
  }
  return (
    <main className="proof-page" id="main-content" tabIndex={-1}>
      <div className="eyebrow">OFFLINE VERIFICATION / NO LOGIN</div>
      <h1>Verify evidence</h1>
      <p>Files stay on your device. Verification makes no network requests.</p>
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
        <button className="primary" onClick={() => void verify()}>
          Verify locally
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
                await createReport(bytes, report),
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
