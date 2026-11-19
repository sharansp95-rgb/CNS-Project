import { it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { execFileSync } from "node:child_process";
import * as c from "../src/crypto";
import { verifyEvidence, verifyReceipt } from "../src/evidenceVerify";
const root = fileURLToPath(new URL("../../../", import.meta.url)),
  corpus = root + "tests/fixtures/evidence_corpus/";
const manifest = JSON.parse(
  readFileSync(corpus + "expected_verdicts.json", "utf8"),
);
for (const [name, entry] of Object.entries(manifest) as [string, any][]) {
  it("Python/browser evidence verdict parity: " + name, async () => {
    const bytes = new Uint8Array(readFileSync(corpus + entry.file));
    const receipt = entry.receipt
        ? JSON.parse(readFileSync(corpus + entry.receipt, "utf8"))
        : undefined,
      key = readFileSync(corpus + "tsa_public.pem", "utf8");
    const browser = await verifyEvidence(bytes, receipt, key);
    const code = `import sys,json,base64;sys.path.insert(0,sys.argv[1]);from tools.verify_transcript import verify_evidence;from crypto_engine.evidence_tools import verify_receipt;d=json.load(sys.stdin);raw=base64.b64decode(d['bytes']);r=verify_evidence(json.loads(raw));receipt=d.get('receipt');\nif receipt and not verify_receipt(receipt,raw,d['key'].encode()):r.bad('receipt invalid',check='timestamp receipt')\nprint(json.dumps(dict(valid=r.valid,index=r.failures[0][0] if r.failures else None)))`;
    const python = JSON.parse(
      execFileSync(root + ".venv/bin/python", ["-c", code, root], {
        input: JSON.stringify({ bytes: c.b64(bytes), receipt, key }),
        encoding: "utf8",
      }),
    );
    expect(browser.valid).toBe(entry.valid);
    expect(browser.valid).toBe(python.valid);
    expect(browser.failures[0]?.index ?? null).toBe(python.index);
    if (entry.index !== null)
      expect(browser.failures[0]?.index).toBe(entry.index);
  });
}
it("valid receipt binds exact file bytes and the independently pinned public key", async () => {
  const bytes = new Uint8Array(readFileSync(corpus + "valid_v2.json")),
    receipt = JSON.parse(readFileSync(corpus + "valid_receipt.json", "utf8")),
    key = readFileSync(corpus + "tsa_public.pem", "utf8");
  expect(await verifyReceipt(receipt, bytes, key)).toBe(true);
  expect(await verifyReceipt(receipt, c.concat(bytes, c.utf8("\n")), key)).toBe(
    false,
  );
  expect(await verifyReceipt({ ...receipt, total: 999 }, bytes, key)).toBe(
    false,
  );
});
