use serde::Deserialize;
use zkapi_types::Felt252;

use crate::error::AuthError;

#[derive(Debug, Clone)]
pub struct IndexerClient {
    base_url: String,
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
        Self {
            base_url: base_url.into().trim_end_matches('/').to_string(),
        }
    }

    pub async fn root(&self) -> Result<Felt252, AuthError> {
        let url = format!("{}/v1/tree/root", self.base_url);
        let response = reqwest::Client::new()
            .get(&url)
            .send()
            .await
            .map_err(|err| AuthError::Indexer(err.to_string()))?;
        let response = response
            .error_for_status()
            .map_err(|err| AuthError::Indexer(err.to_string()))?;
        let payload: TreeRootResponse = response
            .json()
            .await
            .map_err(|err| AuthError::Indexer(err.to_string()))?;
        Ok(payload.root)
    }

    pub async fn next_note_id(&self) -> Result<u32, AuthError> {
        let url = format!("{}/v1/tree/next-note-id", self.base_url);
        let response = reqwest::Client::new()
            .get(&url)
            .send()
            .await
            .map_err(|err| AuthError::Indexer(err.to_string()))?;
        let response = response
            .error_for_status()
            .map_err(|err| AuthError::Indexer(err.to_string()))?;
        let payload: NextNoteIdResponse = response
            .json()
            .await
            .map_err(|err| AuthError::Indexer(err.to_string()))?;
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
        let response = reqwest::Client::new()
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
