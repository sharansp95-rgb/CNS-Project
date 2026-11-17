import { describe, expect, it } from "vitest";
import { describeRejection } from "../src/securityWarning";

describe("describeRejection", () => {
  it("says what the receiver's real checks found, in plain words", () => {
    expect(describeRejection("message_rejected", "decryption_failed")).toMatch(
      /altered.*rejected/,
    );
    expect(describeRejection("message_rejected", "replay_duplicate")).toMatch(
      /Duplicate or old message — rejected/,
    );
    expect(describeRejection("chain_warning", "chain_gap", 1)).toBe(
      "1 message missing — never arrived (hash-chain gap).",
    );
    expect(describeRejection("chain_warning", "chain_gap", 3)).toContain(
      "3 messages missing",
    );
    expect(describeRejection("message_rejected", "chain_broken")).toMatch(
      /out of order/,
    );
    expect(describeRejection("message_rejected", "something_new")).toBe(
      "Message rejected: something_new.",
    );
  });
});
