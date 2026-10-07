//! The operator's indexer. Every call is bounded (design §6.4 E0): the
//! indexer is operator-run, and the mutual close and request preparation
//! read it while holding the wallet's locks, which every exit route takes
//! too. A call that connects and never answers, or drips its body, fails
//! after `CALL_TIMEOUT` instead of holding those locks.

use std::time::Duration;

use serde::Deserialize;
use zkapi_types::Felt252;

use crate::error::AuthError;

/// E0's `CALL_TIMEOUT`, connect and full body included (shortened in tests,
/// like the exit routes' own bound).
#[cfg(not(test))]
pub(crate) const CALL_TIMEOUT: Duration =
    Duration::from_secs(zkapi_client::exit_policy::CALL_TIMEOUT_SECONDS);
#[cfg(test)]
pub(crate) const CALL_TIMEOUT: Duration = Duration::from_millis(1_500);

#[derive(Debug, Clone)]
pub struct IndexerClient {
    base_url: String,
    http: reqwest::Client,
}

#[derive(Debug, Deserialize)]
struct TreeRootResponse {
    root: Felt252,
}

#[derive(Debug, Deserialize)]
struct TreePathResponse {
    siblings: Vec<Felt252>,
}

#[derive(Debug, Deserialize)]
struct TreeLeafResponse {
    leaf: Option<Felt252>,
}

#[derive(Debug, Deserialize)]
struct NextNoteIdResponse {
    next_note_id: u32,
}

impl IndexerClient {
    pub fn new(base_url: impl Into<String>) -> Self {
        Self::with_timeout(base_url, CALL_TIMEOUT)
    }

    /// An indexer client whose every call (connect and full body) is bounded
    /// by `timeout`.
    pub fn with_timeout(base_url: impl Into<String>, timeout: Duration) -> Self {
        let http = reqwest::Client::builder()
            .connect_timeout(timeout)
            .timeout(timeout)
            .build()
            .unwrap_or_default();
        Self {
            base_url: base_url.into().trim_end_matches('/').to_string(),
            http,
        }
    }

    pub async fn root(&self) -> Result<Felt252, AuthError> {
        let payload: TreeRootResponse = self.get(format!("{}/v1/tree/root", self.base_url)).await?;
        Ok(payload.root)
    }

    /// The root and `note_id`'s path, read together within one
    /// `CALL_TIMEOUT` (E0): the pair the mutual close and a request prove
    /// against.
    pub async fn root_and_path(&self, note_id: u32) -> Result<(Felt252, Vec<Felt252>), AuthError> {
        tokio::time::timeout(CALL_TIMEOUT, async {
            Ok::<_, AuthError>((self.root().await?, self.note_path(note_id).await?))
        })
        .await
        .map_err(|_| AuthError::Indexer("the indexer did not answer in time".into()))?
    }

    pub async fn next_note_id(&self) -> Result<u32, AuthError> {
        let payload: NextNoteIdResponse = self
            .get(format!("{}/v1/tree/next-note-id", self.base_url))
            .await?;
        Ok(payload.next_note_id)
    }

    pub async fn note_path(&self, note_id: u32) -> Result<Vec<Felt252>, AuthError> {
        self.path(format!("{}/v1/tree/notes/{note_id}/path", self.base_url))
            .await
    }

    pub async fn zero_path(&self, note_id: u32) -> Result<Vec<Felt252>, AuthError> {
        self.path(format!(
            "{}/v1/tree/notes/{note_id}/zero-path",
            self.base_url
        ))
        .await
    }

    /// The leaf the indexer's tree holds at `note_id`, from the same view as
    /// its path; zero where no note is.
    pub async fn note_leaf(&self, note_id: u32) -> Result<Felt252, AuthError> {
        let payload: TreeLeafResponse = self
            .get(format!("{}/v1/tree/notes/{note_id}/path", self.base_url))
            .await?;
        payload
            .leaf
            .ok_or_else(|| AuthError::Indexer("the indexer's note path carries no leaf".into()))
    }

    async fn path(&self, url: String) -> Result<Vec<Felt252>, AuthError> {
        let payload: TreePathResponse = self.get(url).await?;
        Ok(payload.siblings)
    }

    async fn get<T: serde::de::DeserializeOwned>(&self, url: String) -> Result<T, AuthError> {
        let response = self
            .http
            .get(&url)
            .send()
            .await
            .map_err(|err| AuthError::Indexer(err.to_string()))?;
        let response = response
            .error_for_status()
            .map_err(|err| AuthError::Indexer(err.to_string()))?;
        response
            .json()
            .await
            .map_err(|err| AuthError::Indexer(err.to_string()))
    }
}
