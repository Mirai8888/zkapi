const ABI = Object.freeze({
  deposit: "c588341c",
  mutualClose: "7fca9c82",
  initiateEscapeWithdrawal: "9073639b",
  finalizeEscapeWithdrawal: "ff8f5585",
  challengePeriod: "f3f480d9",
  legacyChallengePeriod: "c3a079ed",
  currentRoot: "fdab463d",
  nextNoteId: "7a2043a3",
  notes: "9f18e4ed",
  noteDeposited: "0x7c83dba8534bea9e30d6444f9ca6462dc906897f9938d220dbbe4358c1f7a063",
  mutualCloseEvent: "0x1f43fa4711ca18e1d26398f26bf598bd3a62992cdd0e84f055f2bb506e9d7031",
  escapeInitiatedEvent: "0xb0d1eb7131bcf3c6dd53517f6fa90bf7cc94178eb0eb5e0a1f204abe3b839cdf",
  escapeFinalizedEvent: "0x163f2e46c4004f0ed9682e2db8c84efac31310720266b17ea9904ba348c26504",
  // EscapeWithdrawalChallenged(uint32 indexed noteId, uint256 nullifier, uint256 restoredRoot)
  escapeChallengedEvent: "0x5cc5343b84cd949969f3ccc4ea44315630280857b9e591cc1ab48dbb9e6a3581",
  // Hardened vault (vault_revision 2) only. A finalized escape whose push to
  // the destination failed credits it instead:
  // EscapePayoutDeferred(uint32 indexed noteId, address indexed destination, uint128 amount)
  // precedes EscapeWithdrawalFinalized in the same receipt.
  escapePayoutDeferredEvent: "0x1bd006afb1f419c06bdcfcba16d47a9c4c8569f843228da165bdaec644bfa942",
  // EscapePayoutClaimed(address indexed destination, uint128 amount)
  escapePayoutClaimedEvent: "0x6bf75371d42e9753c0913bf8fcecb651e8db173d99d7da0e4d836e91512bbe27",
  claimEscapePayout: "88c10aee",
  escapePayoutCredits: "91f6e93a",
});

// Execution gas the hardened vault forwards when it pushes an escape payout
// (ESCAPE_PAYOUT_GAS()). A destination that needs more is only credited.
const ESCAPE_PAYOUT_GAS = 100_000;

function abiWord(value) {
  const hex = typeof value === "string" ? value.replace(/^0x/, "") : BigInt(value).toString(16);
  if (!/^[0-9a-fA-F]+$/.test(hex) || hex.length > 64) {
    throw new Error("Value cannot be encoded for the vault contract.");
  }
  return hex.padStart(64, "0");
}

function addressWord(address) {
  if (!/^0x[0-9a-fA-F]{40}$/.test(address || "")) {
    throw new Error("MetaMask returned an invalid account address.");
  }
  return abiWord(address);
}

function destinationWord(destination) {
  if (!/^0x[0-9a-fA-F]{40}$/.test(destination || "")) {
    throw new Error("The escape payout destination is not a valid address.");
  }
  return abiWord(destination);
}

function callData(selector, words) {
  return `0x${selector}${words.join("")}`;
}

function toBytes32(felt) {
  return `0x${String(felt).replace(/^0x/, "").padStart(64, "0")}`;
}

function normalizedEscapePeriod(seconds) {
  return Math.max(1, Number(seconds) || 24 * 60 * 60);
}

function escapePeriodLabel(seconds) {
  const value = normalizedEscapePeriod(seconds);
  if (value % 86_400 === 0) return `${value / 86_400}-day`;
  if (value % 3_600 === 0) return `${value / 3_600}-hour`;
  if (value % 60 === 0) return `${value / 60}-minute`;
  return `${value}-second`;
}

function escapePeriodPhrase(seconds) {
  const value = normalizedEscapePeriod(seconds);
  if (value % 86_400 === 0) {
    const days = value / 86_400;
    return `${days} ${days === 1 ? "day" : "days"}`;
  }
  if (value % 3_600 === 0) {
    const hours = value / 3_600;
    return `${hours} ${hours === 1 ? "hour" : "hours"}`;
  }
  if (value % 60 === 0) {
    const minutes = value / 60;
    return `${minutes} ${minutes === 1 ? "minute" : "minutes"}`;
  }
  return `${value} ${value === 1 ? "second" : "seconds"}`;
}

function escapePeriodBadge(seconds) {
  const value = normalizedEscapePeriod(seconds);
  if (value >= 3_600) return `${Math.round(value / 3_600)}h`;
  if (value >= 60) return `${Math.round(value / 60)}m`;
  return `${value}s`;
}

function encodeDeposit(plan, amount) {
  if (!Array.isArray(plan?.zero_path) || plan.zero_path.length !== 32) {
    throw new Error("The private note has an invalid 32-level deposit path.");
  }
  return callData(ABI.deposit, [
    abiWord(toBytes32(plan.commitment)),
    abiWord(amount),
    ...plan.zero_path.map((value) => abiWord(value)),
  ]);
}

function decodeBase64(value) {
  if (typeof value !== "string" || !value) throw new Error("The daemon returned an empty withdrawal proof.");
  try {
    if (typeof atob === "function") {
      const decoded = atob(value);
      return Uint8Array.from(decoded, (character) => character.charCodeAt(0));
    }
    if (typeof Buffer === "function") return Uint8Array.from(Buffer.from(value, "base64"));
  } catch (_) {
    throw new Error("The daemon returned malformed base64 proof data.");
  }
  throw new Error("This browser cannot decode the withdrawal proof.");
}

function bytesHex(bytes) {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

function destinationHex(value) {
  if (typeof value === "string" && /^0x[0-9a-fA-F]{40}$/.test(value)) return value.toLowerCase();
  if (!Array.isArray(value) || value.length !== 20
      || value.some((byte) => !Number.isInteger(byte) || byte < 0 || byte > 255)) {
    throw new Error("The daemon returned an invalid withdrawal destination.");
  }
  return `0x${bytesHex(value)}`;
}

function encodeWithdrawal(plan, expectedMode, expectedDestination, expectedVault) {
  const mode = String(expectedMode || "").toLowerCase();
  if (!['mutual', 'escape'].includes(mode) || plan?.mode !== mode) {
    throw new Error("The daemon returned a different withdrawal mode than requested.");
  }
  if (plan?.proof?.backend !== "groth16_bn254") {
    throw new Error("The daemon returned an unsupported withdrawal proof backend.");
  }
  if (!Array.isArray(plan.siblings) || plan.siblings.length !== 32) {
    throw new Error("The daemon returned an invalid 32-level withdrawal path.");
  }
  const inputs = plan.public_inputs || {};
  const destination = destinationHex(inputs.destination);
  if (destination !== String(expectedDestination || "").toLowerCase()) {
    throw new Error("The proof destination does not match the requested withdrawal address.");
  }
  if (expectedVault && String(inputs.contract_address).toLowerCase() !== String(expectedVault).toLowerCase()) {
    throw new Error("The withdrawal proof is bound to a different vault contract.");
  }
  if (Boolean(inputs.has_clearance) !== (mode === "mutual")) {
    throw new Error("The withdrawal proof has the wrong server-clearance state.");
  }
  const proof = decodeBase64(plan.proof.proof);
  if (proof.length !== 256) {
    throw new Error("The Groth16 withdrawal proof must contain exactly 256 bytes.");
  }

  const tuple = [
    inputs.protocol_version,
    inputs.chain_id,
    inputs.contract_address,
    inputs.active_root,
    inputs.state_signing_key_x,
    inputs.state_signing_key_y,
    inputs.clearance_signing_key_x,
    inputs.clearance_signing_key_y,
    inputs.note_id,
    inputs.final_balance,
    destination,
    inputs.withdrawal_nullifier,
    inputs.has_clearance ? 1 : 0,
    inputs.withdrawal_tag,
  ].map(abiWord);
  // The static tuple occupies 14 words, followed by the bytes offset and
  // the 32-word Merkle path. The dynamic proof therefore starts at word 47.
  const head = [...tuple, abiWord(47n * 32n), ...plan.siblings.map(abiWord)];
  const tail = [abiWord(proof.length), ...Array.from({ length: 8 }, (_, index) => (
    bytesHex(proof.slice(index * 32, (index + 1) * 32))
  ))];
  const selector = mode === "mutual" ? ABI.mutualClose : ABI.initiateEscapeWithdrawal;
  return callData(selector, [...head, ...tail]);
}

function encodeFinalizeEscape(noteId) {
  return callData(ABI.finalizeEscapeWithdrawal, [abiWord(noteId)]);
}

function encodeClaimEscapePayout(destination) {
  return callData(ABI.claimEscapePayout, [destinationWord(destination)]);
}

function encodeEscapePayoutCredits(destination) {
  return callData(ABI.escapePayoutCredits, [destinationWord(destination)]);
}

function vaultLog(log, vaultAddress) {
  return log?.removed !== true
    && String(log?.address || "").toLowerCase() === String(vaultAddress || "").toLowerCase();
}

// The low 20 bytes of an indexed address topic.
function topicAddress(topic) {
  const hex = String(topic || "").replace(/^0x/, "");
  return /^[0-9a-fA-F]{40,64}$/.test(hex) ? `0x${hex.slice(-40)}`.toLowerCase() : null;
}

function firstWord(data) {
  const hex = String(data || "").replace(/^0x/, "");
  return /^[0-9a-fA-F]{64}/.test(hex) ? BigInt(`0x${hex.slice(0, 64)}`) : null;
}

/**
 * The EscapePayoutDeferred log of a finalization receipt: the vault closed
 * the escape but could not push its balance to the destination, so it
 * credited escapePayoutCredits(destination) instead. Matching is deliberately
 * lenient (any non-removed vault log with this topic, note and destination),
 * so a doubtful receipt is reported as credited, never as paid.
 */
function escapePayoutDeferred(receipt, vaultAddress, noteId, destination) {
  for (const log of receipt?.logs || []) {
    const topics = log?.topics;
    if (!vaultLog(log, vaultAddress) || !Array.isArray(topics) || topics.length !== 3
        || String(topics[0]).toLowerCase() !== ABI.escapePayoutDeferredEvent) continue;
    let loggedNoteId;
    try {
      loggedNoteId = BigInt(topics[1]);
    } catch (_) {
      continue;
    }
    if (loggedNoteId !== BigInt(noteId)
        || topicAddress(topics[2]) !== String(destination || "").toLowerCase()) continue;
    return { amount: firstWord(log.data) };
  }
  return null;
}

/**
 * The EscapePayoutClaimed log that proves claimEscapePayout paid `destination`.
 * Matching is strict: the indexed word must be exactly that address.
 */
function parseEscapePayoutClaim(receipt, vaultAddress, destination) {
  if (!/^0x[0-9a-fA-F]{40}$/.test(destination || "")) return null;
  for (const log of receipt?.logs || []) {
    const topics = log?.topics;
    if (!vaultLog(log, vaultAddress) || !Array.isArray(topics) || topics.length !== 2
        || String(topics[0]).toLowerCase() !== ABI.escapePayoutClaimedEvent
        || !/^0x[0-9a-fA-F]{64}$/.test(topics[1] || "")
        || BigInt(topics[1]) !== BigInt(destination)) continue;
    const amount = firstWord(log.data);
    if (amount == null || amount === 0n) continue;
    return { destination: destination.toLowerCase(), amount };
  }
  return null;
}

function parseWithdrawalReceipt(receipt, vaultAddress, mode) {
  const expectedTopic = mode === "mutual" ? ABI.mutualCloseEvent
    : mode === "escape" ? ABI.escapeInitiatedEvent
      : mode === "finalize" ? ABI.escapeFinalizedEvent : null;
  if (!expectedTopic) throw new Error("Unknown withdrawal receipt mode.");
  for (const log of receipt?.logs || []) {
    if (log.address?.toLowerCase() !== vaultAddress.toLowerCase()
        || log.topics?.[0]?.toLowerCase() !== expectedTopic) continue;
    const data = String(log.data || "").replace(/^0x/, "");
    const minimumWords = mode === "escape" ? 5 : 3;
    if (log.topics.length < 2 || data.length < minimumWords * 64) continue;
    const result = {
      noteId: BigInt(log.topics[1]),
      finalBalance: BigInt(`0x${data.slice(64, 128)}`),
      destination: `0x${data.slice(128 + 24, 192)}`.toLowerCase(),
    };
    if (mode === "escape") {
      result.challengeDeadline = BigInt(`0x${data.slice(192, 256)}`);
    }
    if (mode === "finalize") {
      // EscapeWithdrawalFinalized alone does not prove the destination was
      // paid: on a hardened vault a failed push is credited instead.
      const credit = escapePayoutDeferred(receipt, vaultAddress, result.noteId, result.destination);
      result.payoutCredited = Boolean(credit);
      if (credit) result.creditedAmount = credit.amount ?? result.finalBalance;
    }
    return result;
  }
  return null;
}

function parseNoteDeposited(receipt, vaultAddress) {
  for (const log of receipt?.logs || []) {
    if (log.address?.toLowerCase() !== vaultAddress.toLowerCase()
        || log.topics?.[0]?.toLowerCase() !== ABI.noteDeposited) continue;
    const data = String(log.data || "").replace(/^0x/, "");
    if (log.topics.length >= 3 && data.length >= 192) {
      return {
        noteId: BigInt(log.topics[1]),
        commitment: log.topics[2],
        amount: BigInt(`0x${data.slice(0, 64)}`),
        expiryTs: BigInt(`0x${data.slice(64, 128)}`),
        newRoot: BigInt(`0x${data.slice(128, 192)}`),
      };
    }
  }
  return null;
}

const walletCodec = Object.freeze({
  ABI,
  ESCAPE_PAYOUT_GAS,
  abiWord,
  addressWord,
  callData,
  encodeClaimEscapePayout,
  encodeDeposit,
  encodeEscapePayoutCredits,
  encodeFinalizeEscape,
  encodeWithdrawal,
  escapePeriodBadge,
  escapePeriodLabel,
  escapePeriodPhrase,
  parseEscapePayoutClaim,
  parseNoteDeposited,
  parseWithdrawalReceipt,
});

export default walletCodec;
export { ABI, ESCAPE_PAYOUT_GAS, abiWord, addressWord, callData, encodeClaimEscapePayout, encodeDeposit, encodeEscapePayoutCredits, encodeFinalizeEscape, encodeWithdrawal, escapePeriodBadge, escapePeriodLabel, escapePeriodPhrase, parseEscapePayoutClaim, parseNoteDeposited, parseWithdrawalReceipt };
