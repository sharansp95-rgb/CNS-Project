/** Plain-language text for the receiver's own rejection reasons (session.ts reject()). */
export function describeRejection(
  kind: string,
  reason: string,
  missing = 0,
): string {
  switch (reason) {
    case "decryption_failed":
      return "Message was altered in transit — rejected (authentication tag failed).";
    case "replay_duplicate":
      return "Duplicate or old message — rejected (already seen).";
    case "chain_gap":
      return missing > 0
        ? `${missing} message${missing === 1 ? "" : "s"} missing — never arrived (hash-chain gap).`
        : "A message is missing — it never arrived (hash-chain gap).";
    case "chain_broken":
      return "Message out of order — rejected (hash chain does not match).";
    case "signature_failed":
      return "Message signature is not valid — rejected.";
    case "stale_timestamp":
      return "Message is too old — rejected.";
    default:
      return kind === "chain_warning"
        ? `Warning: ${reason}.`
        : `Message rejected: ${reason}.`;
  }
}
