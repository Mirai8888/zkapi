import test from "node:test";
import assert from "node:assert/strict";

import wallet from "../wallet.js";

test("escape-period labels follow the deployed vault duration", () => {
  assert.equal(wallet.ABI.currentRoot, "fdab463d");
  assert.equal(wallet.ABI.challengePeriod, "f3f480d9");
  assert.equal(wallet.ABI.legacyChallengePeriod, "c3a079ed");
  assert.equal(wallet.escapePeriodLabel(60), "1-minute");
  assert.equal(wallet.escapePeriodPhrase(60), "1 minute");
  assert.equal(wallet.escapePeriodBadge(60), "1m");
  assert.equal(wallet.escapePeriodPhrase(86_400), "1 day");
  assert.equal(wallet.escapePeriodPhrase(172_800), "2 days");
  assert.equal(wallet.escapePeriodBadge(30), "30s");
});

test("deposit calldata uses the deployed vault signature and 32 static siblings", () => {
  const plan = {
    commitment: "0x2a",
    zero_path: Array.from({ length: 32 }, (_, index) => `0x${(index + 1).toString(16)}`),
  };
  const encoded = wallet.encodeDeposit(plan, 100_000n);
  assert.ok(encoded.startsWith("0xc588341c"));
  assert.equal(encoded.length, 2 + 8 + (34 * 64));
  assert.equal(encoded.slice(10, 74), wallet.abiWord("0x2a"));
  assert.equal(encoded.slice(74, 138), wallet.abiWord(100_000n));
});

test("NoteDeposited receipt parsing returns canonical note id and expiry", () => {
  const vault = "0x590df9abbfb21074016daa486c771ae0af729ee2";
  const receipt = {
    logs: [{
      address: vault.toUpperCase().replace("0X", "0x"),
      topics: [wallet.ABI.noteDeposited, `0x${wallet.abiWord(21n)}`, `0x${wallet.abiWord(42n)}`],
      data: `0x${wallet.abiWord(100_000n)}${wallet.abiWord(1_800_000_000n)}${wallet.abiWord(99n)}`,
    }],
  };
  assert.deepEqual(wallet.parseNoteDeposited(receipt, vault), {
    noteId: 21n,
    commitment: `0x${wallet.abiWord(42n)}`,
    amount: 100_000n,
    expiryTs: 1_800_000_000n,
    newRoot: 99n,
  });
});

function withdrawalPlan(mode = "mutual") {
  return {
    mode,
    public_inputs: {
      protocol_version: 1,
      chain_id: 11_155_111,
      contract_address: "0x590df9abbfb21074016daa486c771ae0af729ee2",
      active_root: "0x11",
      state_signing_key_x: "0x12",
      state_signing_key_y: "0x13",
      clearance_signing_key_x: "0x14",
      clearance_signing_key_y: "0x15",
      note_id: 21,
      final_balance: 1_850_000,
      destination: Array(20).fill(0x22),
      withdrawal_nullifier: "0x16",
      has_clearance: mode === "mutual",
      withdrawal_tag: "0x17",
    },
    siblings: Array.from({ length: 32 }, (_, index) => `0x${(index + 1).toString(16)}`),
    proof: {
      backend: "groth16_bn254",
      proof: Buffer.from(Array.from({ length: 256 }, (_, index) => index)).toString("base64"),
    },
  };
}

test("mutual-close calldata encodes the exact static tuple, dynamic proof, and path", () => {
  const plan = withdrawalPlan("mutual");
  const destination = "0x2222222222222222222222222222222222222222";
  const encoded = wallet.encodeWithdrawal(plan, "mutual", destination, plan.public_inputs.contract_address);
  assert.ok(encoded.startsWith(`0x${wallet.ABI.mutualClose}`));
  assert.equal(encoded.length, 2 + 8 + (56 * 64));
  assert.equal(encoded.slice(10 + (14 * 64), 10 + (15 * 64)), wallet.abiWord(1_504n));
  assert.equal(encoded.slice(10 + (47 * 64), 10 + (48 * 64)), wallet.abiWord(256n));
  assert.equal(encoded.slice(-64), Buffer.from(Array.from({ length: 32 }, (_, index) => index + 224)).toString("hex"));
});

test("escape calldata and finalization selector use deployed signatures", () => {
  const plan = withdrawalPlan("escape");
  const destination = "0x2222222222222222222222222222222222222222";
  assert.ok(wallet.encodeWithdrawal(plan, "escape", destination).startsWith(`0x${wallet.ABI.initiateEscapeWithdrawal}`));
  assert.equal(wallet.encodeFinalizeEscape(21), `0x${wallet.ABI.finalizeEscapeWithdrawal}${wallet.abiWord(21)}`);
});

test("withdrawal encoder rejects destination and clearance substitutions", () => {
  const plan = withdrawalPlan("mutual");
  assert.throws(() => wallet.encodeWithdrawal(plan, "mutual", "0x3333333333333333333333333333333333333333"), /destination/);
  plan.public_inputs.has_clearance = false;
  assert.throws(() => wallet.encodeWithdrawal(plan, "mutual", "0x2222222222222222222222222222222222222222"), /clearance/);
});

test("withdrawal events expose note, destination, balance, and escape deadline", () => {
  const vault = "0x590df9abbfb21074016daa486c771ae0af729ee2";
  const receipt = {
    logs: [{
      address: vault,
      topics: [wallet.ABI.escapeInitiatedEvent, `0x${wallet.abiWord(21n)}`],
      data: `0x${wallet.abiWord(99n)}${wallet.abiWord(1_850_000n)}${wallet.addressWord("0x2222222222222222222222222222222222222222")}${wallet.abiWord(1_900_000_000n)}${wallet.abiWord(101n)}`,
    }],
  };
  assert.deepEqual(wallet.parseWithdrawalReceipt(receipt, vault, "escape"), {
    noteId: 21n,
    finalBalance: 1_850_000n,
    destination: "0x2222222222222222222222222222222222222222",
    challengeDeadline: 1_900_000_000n,
  });
});

// The two receipt layouts pinned by the vault's
// test_finalizeReceiptTellsPaidFromCreditedPayout: a paid finalization emits
// only EscapeWithdrawalFinalized; a credited one emits EscapePayoutDeferred
// (topics [topic0, noteId, destination], data abi.encode(uint128 amount))
// before the identical EscapeWithdrawalFinalized.
const PAYOUT_VAULT = "0x590df9abbfb21074016daa486c771ae0af729ee2";
const PAYOUT_DESTINATION = "0x5615deb798bb3e4dfa0139dfa1b3d433cc23b72f";
const word = (value) => `0x${wallet.abiWord(value)}`;

function finalizedLog(destination = PAYOUT_DESTINATION, noteId = 0n) {
  return {
    address: PAYOUT_VAULT,
    topics: [wallet.ABI.escapeFinalizedEvent, word(noteId)],
    data: `0x${wallet.abiWord(99n)}${wallet.abiWord(700_000n)}${wallet.abiWord(destination)}`,
  };
}

function deferredLog({ noteId = 0n, destination = PAYOUT_DESTINATION, amount = 700_000n, ...overrides } = {}) {
  return {
    address: PAYOUT_VAULT,
    topics: [wallet.ABI.escapePayoutDeferredEvent, word(noteId), word(destination)],
    data: word(amount),
    removed: false,
    ...overrides,
  };
}

test("payout-credit selectors and topics match the hardened vault", () => {
  assert.equal(wallet.ABI.claimEscapePayout, "88c10aee");
  assert.equal(wallet.ABI.escapePayoutCredits, "91f6e93a");
  assert.equal(wallet.ABI.escapePayoutDeferredEvent,
    "0x1bd006afb1f419c06bdcfcba16d47a9c4c8569f843228da165bdaec644bfa942");
  assert.equal(wallet.ABI.escapePayoutClaimedEvent,
    "0x6bf75371d42e9753c0913bf8fcecb651e8db173d99d7da0e4d836e91512bbe27");
  assert.equal(wallet.ESCAPE_PAYOUT_GAS, 100_000);
  assert.equal(wallet.encodeClaimEscapePayout(PAYOUT_DESTINATION),
    `0x88c10aee${"0".repeat(24)}${PAYOUT_DESTINATION.slice(2)}`);
  assert.equal(wallet.encodeEscapePayoutCredits(PAYOUT_DESTINATION),
    `0x91f6e93a${"0".repeat(24)}${PAYOUT_DESTINATION.slice(2)}`);
  assert.throws(() => wallet.encodeClaimEscapePayout("0x1234"), /destination/);
});

test("a credited escape finalization is reported as credited, never as paid", () => {
  const paid = wallet.parseWithdrawalReceipt({ status: "0x1", logs: [finalizedLog()] }, PAYOUT_VAULT, "finalize");
  assert.deepEqual(paid, {
    noteId: 0n,
    finalBalance: 700_000n,
    destination: PAYOUT_DESTINATION,
    payoutCredited: false,
  });

  const credited = wallet.parseWithdrawalReceipt({ status: "0x1", logs: [deferredLog(), finalizedLog()] },
    PAYOUT_VAULT, "finalize");
  assert.deepEqual(credited, {
    noteId: 0n,
    finalBalance: 700_000n,
    destination: PAYOUT_DESTINATION,
    payoutCredited: true,
    creditedAmount: 700_000n,
  });
  assert.equal(credited.payoutVerified, undefined);

  // Checksummed or upper-case addresses and topics still match.
  const mixedCase = deferredLog();
  mixedCase.address = PAYOUT_VAULT.toUpperCase().replace("0X", "0x");
  mixedCase.topics = mixedCase.topics.map((topic) => topic.toUpperCase().replace("0X", "0x"));
  assert.equal(wallet.parseWithdrawalReceipt({ logs: [finalizedLog(), mixedCase] }, PAYOUT_VAULT, "finalize")
    .payoutCredited, true);
});

test("only the vault's own non-removed credit for this note and destination counts", () => {
  const other = "0x1111111111111111111111111111111111111111";
  for (const log of [
    deferredLog({ removed: true }),
    deferredLog({ address: other }),
    deferredLog({ noteId: 1n }),
    deferredLog({ destination: other }),
    { ...deferredLog(), topics: deferredLog().topics.slice(0, 2) },
    { ...deferredLog(), topics: [wallet.ABI.escapePayoutClaimedEvent, word(PAYOUT_DESTINATION), word(0n)] },
  ]) {
    const parsed = wallet.parseWithdrawalReceipt({ logs: [log, finalizedLog()] }, PAYOUT_VAULT, "finalize");
    assert.equal(parsed.payoutCredited, false);
    assert.equal(parsed.creditedAmount, undefined);
  }
  // Doubtful data still reports a credit (with the finalized balance).
  const noData = wallet.parseWithdrawalReceipt({ logs: [deferredLog({ data: "0x" }), finalizedLog()] },
    PAYOUT_VAULT, "finalize");
  assert.equal(noData.payoutCredited, true);
  assert.equal(noData.creditedAmount, 700_000n);
  // A start or mutual-close receipt never carries the credit flag.
  assert.equal(wallet.parseWithdrawalReceipt({ logs: [deferredLog()] }, PAYOUT_VAULT, "finalize"), null);
});

test("only an exact EscapePayoutClaimed log for the destination proves a claim", () => {
  const claimed = (overrides = {}) => ({
    address: PAYOUT_VAULT,
    topics: [wallet.ABI.escapePayoutClaimedEvent, word(PAYOUT_DESTINATION)],
    data: word(700_000n),
    ...overrides,
  });
  assert.deepEqual(wallet.parseEscapePayoutClaim({ logs: [claimed()] }, PAYOUT_VAULT, PAYOUT_DESTINATION), {
    destination: PAYOUT_DESTINATION,
    amount: 700_000n,
  });
  assert.deepEqual(wallet.parseEscapePayoutClaim({ logs: [claimed()] }, PAYOUT_VAULT,
    PAYOUT_DESTINATION.toUpperCase().replace("0X", "0x")).amount, 700_000n);
  const other = "0x1111111111111111111111111111111111111111";
  for (const log of [
    claimed({ removed: true }),
    claimed({ address: other }),
    claimed({ topics: [wallet.ABI.escapePayoutClaimedEvent, word(other)] }),
    // Dirty upper bytes are not an exact address word.
    claimed({ topics: [wallet.ABI.escapePayoutClaimedEvent, `0x${"ff".repeat(12)}${PAYOUT_DESTINATION.slice(2)}`] }),
    claimed({ topics: [wallet.ABI.escapePayoutDeferredEvent, word(0n), word(PAYOUT_DESTINATION)] }),
    claimed({ data: "0x" }),
    claimed({ data: word(0n) }),
  ]) {
    assert.equal(wallet.parseEscapePayoutClaim({ logs: [log] }, PAYOUT_VAULT, PAYOUT_DESTINATION), null);
  }
});
