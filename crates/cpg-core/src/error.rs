use thiserror::Error;

#[derive(Debug, Error)]
pub enum CpgError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("(de)serialization error: {0}")]
    Serde(#[from] serde_json::Error),

    #[error("not implemented yet: {0}")]
    NotImplemented(String),

    #[error("extraction failed: {0}")]
    Extraction(String),
}
