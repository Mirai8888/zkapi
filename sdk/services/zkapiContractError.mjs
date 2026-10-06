const CONTRACT_ERRORS = Object.freeze({
    '0x09bde339': {
        code: 'invalid_proof',
        message: 'The vault rejected the withdrawal proof. Refresh the page and prepare the withdrawal again.'
    },
    // StaleRoot(): on a vault with root history the proof's root is still
    // known and only the Merkle siblings are stale against the live root.
    '0x607447de': {
        code: 'stale_root',
        message: 'The vault changed while the withdrawal was being prepared. The Merkle path (and, on older vaults, the proof) must be refreshed.'
    },
    // UnknownRoot(): the proof's root left the vault's recent-root window.
    '0x8c520116': {
        code: 'unknown_root',
        message: 'The vault no longer accepts this withdrawal proof’s Merkle root. The proof must be generated again.'
    },
    // ChallengedNullifier(): an escape at this state was already challenged.
    '0x2845df70': {
        code: 'challenged_nullifier',
        message: 'An escape at this balance state was already challenged, so it cannot escape again. Withdraw from the server-signed next state instead.'
    },
    // InvalidDestination(): a zero payout address.
    '0xac6b05f5': {
        code: 'invalid_destination',
        message: 'The vault rejected the withdrawal address.'
    },
    // Paused(): the owner paused the vault.
    '0x9e87fac8': {
        code: 'vault_paused',
        message: 'The vault is paused by its owner. Withdrawals resume when it is unpaused.'
    },
    '0x947e59c5': {
        code: 'replayed_nullifier',
        message: 'This private state was already used or reserved. Check the withdrawal’s on-chain status before retrying.'
    },
    '0x61a83aab': {
        code: 'note_not_active',
        message: 'This private note is no longer active. Check its on-chain withdrawal status.'
    },
    '0xc52e3eff': {
        code: 'invalid_balance',
        message: 'The withdrawal balance is not valid for this private note.'
    },
    '0x9722445b': {
        code: 'invalid_deployment',
        message: 'The withdrawal proof does not match this zkAPI deployment.'
    },
    '0xd9876be8': {
        code: 'invalid_siblings',
        message: 'The vault rejected the withdrawal Merkle path. Prepare a fresh withdrawal and try again.'
    },
    '0x3be553f2': {
        code: 'not_pending_withdrawal',
        message: 'This note does not have an escape withdrawal waiting to be finalized.'
    },
    '0xf4b3b1bc': {
        code: 'native_transfer_failed',
        message: 'The vault could not return ETH to the withdrawal address.'
    },
    '0x2723e9c2': {
        code: 'invalid_native_value',
        message: 'The ETH transaction value does not match the private-note amount.'
    },
    '0x151f07fe': {
        code: 'challenge_not_expired',
        message: 'The escape safety window has not finished yet.'
    },
    // ZeroAmount(): for claimEscapePayout, the vault holds nothing for that address.
    '0x1f2a2005': {
        code: 'zero_amount',
        message: 'The vault has nothing to pay for this request.'
    }
});

function matchingSelector(value) {
    if (typeof value !== 'string') return null;
    for (const match of value.matchAll(/0x[0-9a-fA-F]{8,}/g)) {
        const selector = match[0].slice(0, 10).toLowerCase();
        if (CONTRACT_ERRORS[selector]) return selector;
    }
    return null;
}

export function contractRevertSelector(error) {
    const queue = [error];
    const seen = new Set();
    while (queue.length) {
        const value = queue.shift();
        if (value == null || seen.has(value)) continue;
        if (typeof value === 'string') {
            const selector = matchingSelector(value);
            if (selector) return selector;
            try {
                queue.push(JSON.parse(value));
            } catch {
                // Most provider messages are plain text rather than JSON.
            }
            continue;
        }
        if (typeof value !== 'object') continue;
        seen.add(value);
        for (const nested of Object.values(value)) queue.push(nested);
    }
    return null;
}

export function contractEstimateError(error) {
    const selector = contractRevertSelector(error);
    const detail = selector ? CONTRACT_ERRORS[selector] : null;
    const providerMessage = error?.shortMessage || error?.message || String(error);
    const wrapped = new Error(detail?.message
        || `Transaction simulation failed: ${providerMessage}`);
    wrapped.name = 'ZkapiContractError';
    wrapped.code = detail?.code || 'gas_estimation_failed';
    wrapped.selector = selector;
    wrapped.cause = error;
    return wrapped;
}
