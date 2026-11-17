import "regenerator-runtime/runtime";
/** Generates a companion entirely in the browser; never posts evidence. */
import { PDFDocument, rgb, type PDFFont } from "pdf-lib";
import fontkit from "@pdf-lib/fontkit";
import latinUrl from "@fontsource/noto-sans/files/noto-sans-latin-400-normal.woff?url";
import devanagariUrl from "@fontsource/noto-sans/files/noto-sans-devanagari-400-normal.woff?url";
import { sha, hex } from "./crypto";
import type { Verification } from "./evidenceVerify";
import { parseDescriptor } from "./attachments/descriptor";
import { parseSignal, isCallMessage } from "./calls/signal";
export async function createReport(
  bytes: Uint8Array,
  report: Verification,
  receipt?: Record<string, any>,
) {
  const evidence = JSON.parse(new TextDecoder().decode(bytes)),
    doc = await PDFDocument.create();
  doc.registerFontkit(fontkit);
  const [latinBytes, devBytes] = await Promise.all([
    fetch(latinUrl).then((r) => r.arrayBuffer()),
    fetch(devanagariUrl).then((r) => r.arrayBuffer()),
  ]);
  const latin = await doc.embedFont(latinBytes, { subset: true }),
    dev = await doc.embedFont(devBytes, { subset: true });
  const supported = new Map<PDFFont, Set<number>>([
    [latin, new Set(latin.getCharacterSet())],
    [dev, new Set(dev.getCharacterSet())],
  ]);
  let page = doc.addPage([595, 842]),
    y = 790,
    pageNumber = 1;
  function footer() {
    page.drawText(
      "Secure Chat / Team 15 — companion report / page " + pageNumber,
      { x: 44, y: 24, size: 8, font: latin, color: rgb(0.35, 0.4, 0.38) },
    );
  }
  function next() {
    footer();
    page = doc.addPage([595, 842]);
    y = 790;
    pageNumber++;
  }
  function glyphs(text: string) {
    const result: { s: string; f: PDFFont }[] = [];
    for (const char of text) {
      const cp = char.codePointAt(0)!,
        font = supported.get(latin)!.has(cp)
          ? latin
          : supported.get(dev)!.has(cp)
            ? dev
            : latin;
      const value = supported.get(font)!.has(cp)
        ? char
        : "\\u{" + cp.toString(16) + "}";
      const tail = result.at(-1);
      if (tail?.f === font) tail.s += value;
      else result.push({ s: value, f: font });
    }
    return result;
  }
  function width(s: string, size: number) {
    return glyphs(s).reduce((n, g) => n + g.f.widthOfTextAtSize(g.s, size), 0);
  }
  function line(text: string, size = 10) {
    if (y < 60) next();
    let x = 44;
    for (const run of glyphs(text)) {
      page.drawText(run.s, {
        x,
        y,
        size,
        font: run.f,
        color: rgb(0.12, 0.18, 0.14),
      });
      x += run.f.widthOfTextAtSize(run.s, size);
    }
    y -= size * 1.6;
  }
  function paragraph(text: unknown, size = 10) {
    for (const input of String(text ?? "").split(/\r?\n/)) {
      let current = "";
      for (const token of input.match(/\S+\s*|\s+/g) || []) {
        if (current && width(current + token, size) > 507) {
          line(current.trimEnd(), size);
          current = "";
        }
        for (const char of token) {
          if (width(current + char, size) > 507 && current) {
            line(current.trimEnd(), size);
            current = "";
          }
          current += char;
        }
      }
      line(current, size);
    }
    y -= 5;
  }
  paragraph("Secure Chat — Evidence companion", 20);
  paragraph(
    "AUTHORITATIVE EVIDENCE: the original signed JSON file. This PDF is an unsigned companion; it is not a substitute for that file.",
    11,
  );
  paragraph(
    "Overall verification: " +
      (report.valid ? "VALID" : "INVALID — do not treat as unaltered evidence"),
    13,
  );
  paragraph("File SHA-256: " + hex(await sha(bytes)), 9);
  paragraph(
    "Format: " +
      evidence.format +
      " / exported by " +
      evidence.exported_by +
      " / exported at " +
      new Date(evidence.exported_at * 1000).toISOString(),
  );
  paragraph("Participants and RSA fingerprints", 14);
  for (const [name, info] of Object.entries(evidence.participants || {}))
    paragraph(name + ": " + (info as any).fingerprint);
  paragraph("Verification failures / hash-chain status", 14);
  if (!report.failures.length)
    paragraph(
      "All checked sender signatures, record hashes, directional chains, final heads and exporter signature passed.",
    );
  for (const fail of report.failures)
    paragraph(
      (fail.index === null ? "File" : "Message #" + fail.index) +
        ": " +
        fail.check +
        " — " +
        fail.detail,
    );
  paragraph("Conversation", 14);
  const records = Array.isArray(evidence.records) ? evidence.records : [];
  for (let i = 0; i < records.length; i++) {
    const row = records[i],
      status = report.messages.find((m) => m.index === i + 1);
    paragraph(
      `#${i + 1} ${row.sender} → ${row.recipient} / ${new Date(row.timestamp * 1000).toISOString()} / seq ${row.seq}`,
      10,
    );
    paragraph(
      "Record verification: " +
        (status?.valid
          ? "PASSED signature/hash/chain checks"
          : "FAILED or not verified"),
    );
    const att = parseDescriptor(String(row.message));
    if (att) {
      // Never print the file key or thumbnail: the PDF lists identity and hashes only.
      paragraph(`Attachment: ${att.name} (${att.mime}, ${att.size} bytes)`, 11);
      paragraph("Plaintext file SHA-256: " + att.pt_sha256, 8);
      paragraph(
        `Stored (encrypted) object SHA-256: ${att.ct_sha256} (${att.ct_size} bytes)`,
        8,
      );
    } else if (isCallMessage(String(row.message))) {
      // Metadata only: the SDP (which contains network addresses) is not printed.
      const sig = parseSignal(String(row.message));
      paragraph(
        sig
          ? sig.type === "record"
            ? `Voice call record (${sig.role}): ${sig.outcome}, ${sig.duration} s, connection ${sig.conn}, DTLS fingerprint check ${sig.fp_match}, spoken words confirmed: ${sig.sas_confirmed ? "yes" : "no"}`
            : `Voice call signaling: ${sig.type}${sig.reason ? " (" + sig.reason + ")" : ""}`
          : "Voice call message (could not be parsed)",
        11,
      );
      if (sig) paragraph("Call id: " + sig.call, 8);
    } else paragraph(row.message, 11);
    if (row.envelope_sha256)
      paragraph("Relayed envelope SHA-256: " + row.envelope_sha256, 8);
  }
  const attachments = records
    .map((row: any, i: number) => ({
      i,
      d: parseDescriptor(String(row.message)),
    }))
    .filter((x: any) => x.d);
  paragraph("Attachments", 14);
  if (!attachments.length) paragraph("No attachments in this conversation.");
  else {
    paragraph(
      "Files are end-to-end encrypted. Each hash below is covered by the sender's signature on its message. Check a file on /verify or with: python tools/verify_transcript.py evidence.json --check-file FILE",
      9,
    );
    for (const { i, d } of attachments) {
      paragraph(`Message #${i + 1}: ${d.name} (${d.mime}, ${d.size} bytes)`);
      paragraph("Plaintext SHA-256: " + d.pt_sha256, 8);
      paragraph("Ciphertext SHA-256: " + d.ct_sha256, 8);
    }
  }
  const calls = records
    .map((row: any, i: number) => ({
      i,
      who: row.sender,
      sig: parseSignal(String(row.message)),
    }))
    .filter((x: any) => x.sig?.type === "record");
  paragraph("Voice calls", 14);
  if (!calls.length) paragraph("No voice call records in this conversation.");
  else {
    paragraph(
      "Calls are peer-to-peer encrypted (DTLS-SRTP); audio is never recorded or stored. Each party signs its own record.",
      9,
    );
    for (const { i, who, sig } of calls)
      paragraph(
        `Message #${i + 1} by ${who}: ${sig.outcome}, ${new Date(sig.started * 1000).toISOString()} for ${sig.duration} s, connection ${sig.conn}, fingerprint ${sig.fp_match}, words confirmed ${sig.sas_confirmed ? "yes" : "no"}`,
        9,
      );
  }
  paragraph("Timestamp receipt", 14);
  if (receipt) {
    paragraph("Receipt verification: " + report.receipt);
    for (const field of [
      "server_time",
      "file_sha256",
      "key_id",
      "corroborated",
      "total",
      "signature",
    ])
      paragraph(field + ": " + receipt[field], 9);
  } else paragraph("No timestamp receipt supplied.");
  paragraph("How to verify", 14);
  paragraph(
    "Keep the exact JSON bytes, optional receipt JSON, and a trusted TSA public PEM. Visit /verify for local browser verification, or run:",
  );
  paragraph(
    "python tools/verify_transcript.py evidence.json --receipt receipt.json --tsa-pubkey tsa-public.pem",
    9,
  );
  paragraph(
    "Pin participant fingerprints independently (--expect-fingerprint). A valid file shows cryptographic consistency with its keys, not a legal identity or proof that statements are true. A receipt relies on the server key and clock and on the submitted hash manifest; retained ciphertext matches do not prove plaintext by themselves.",
  );
  paragraph(
    "Fonts: Noto Sans (SIL Open Font License). Unsupported glyphs are preserved as Unicode escapes, such as \\u{1f642}; the authoritative JSON keeps the original Unicode text.",
    8,
  );
  footer();
  doc.setTitle("Secure Chat Evidence Companion");
  return doc.save();
}
