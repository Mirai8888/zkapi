//! Check the key policy of a release build of `zkapi-proof`:
//!
//! ```text
//! cargo run --release --manifest-path protocol/rust/Cargo.toml -p zkapi-proof --bin release_policy_check
//! ```
//!
//! `cargo test` cannot check this: this crate's tests and examples enable the
//! `dev-setup` feature through its self dev-dependency, and Cargo unifies
//! features across one build. A binary built on its own (`cargo run -p
//! zkapi-proof --bin ...`) activates no dev-dependency, so it sees the library
//! exactly as a production binary that does not enable `dev-setup` does.
//!
//! It fails unless the build accepts only `mpc-1`, refuses the committed
//! development setup with every loader, and refuses development keys
//! relabelled `rehearsal` or `mpc-1` (no ceremony keys are pinned yet).
use std::path::Path;

use anyhow::{ensure, Result};
use zkapi_proof::compact::{
    accepted_setup_ids, dev_setup_build, key_header, setup, strip_key_header, KeyKind,
    RequestProver, RequestVerifier, WithdrawalProver, WithdrawalVerifier, CEREMONY_SETUP_ID,
    CEREMONY_VK_KECCAK256, REHEARSAL_SETUP_ID, RELEASE_SETUP_IDS,
};

fn refused<T>(what: &str, result: Result<T>, expected: &str) -> Result<()> {
    match result {
        Ok(_) => anyhow::bail!("a release build loaded {what}"),
        Err(error) => {
            let message = format!("{error:#}");
            ensure!(
                message.contains(expected),
                "{what} was refused for another reason: {message}"
            );
            Ok(())
        }
    }
}

fn relabel(file: &[u8], setup_id: &str, kind: KeyKind) -> Result<Vec<u8>> {
    let (_, payload) = strip_key_header(file, kind)?;
    let mut bytes = key_header(setup_id, kind)?;
    bytes.extend_from_slice(payload);
    Ok(bytes)
}

fn main() -> Result<()> {
    ensure!(
        !dev_setup_build() && accepted_setup_ids() == RELEASE_SETUP_IDS,
        "this build has the dev-setup feature (it accepts {:?}); run this check on its own: \
         cargo run -p zkapi-proof --bin release_policy_check",
        accepted_setup_ids()
    );
    // Key generation needs no feature (`zkapi setup` links it into the CLI).
    let _generate: fn(&Path) -> Result<()> = |directory| setup(directory);

    let dev = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../setup/v2-concession-dev");
    refused(
        "the development request proving key",
        RequestProver::load(&dev),
        "not accepted",
    )?;
    refused(
        "the development request verifying key",
        RequestVerifier::load(&dev),
        "not accepted",
    )?;
    refused(
        "the development withdrawal proving key",
        WithdrawalProver::load(&dev),
        "not accepted",
    )?;
    refused(
        "the development withdrawal verifying key",
        WithdrawalVerifier::load(&dev),
        "not accepted",
    )?;

    let request_vk = std::fs::read(dev.join("request.vk"))?;
    refused(
        "a development key labelled rehearsal",
        RequestVerifier::from_bytes(&relabel(&request_vk, REHEARSAL_SETUP_ID, KeyKind::Request)?),
        "not accepted",
    )?;
    let expected = if CEREMONY_VK_KECCAK256.is_some() {
        "not the pinned ceremony key"
    } else {
        "no mpc-1 verifying keys are pinned"
    };
    refused(
        "a development key labelled mpc-1",
        RequestVerifier::from_bytes(&relabel(&request_vk, CEREMONY_SETUP_ID, KeyKind::Request)?),
        expected,
    )?;
    println!(
        "release policy ok: accepts {RELEASE_SETUP_IDS:?} with pinned verifying keys \
         ({}); refuses the development setup and relabelled development keys",
        if CEREMONY_VK_KECCAK256.is_some() {
            "pinned"
        } else {
            "none pinned yet"
        }
    );
    Ok(())
}
