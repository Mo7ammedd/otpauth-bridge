use thiserror::Error;

/// Errors intentionally exclude input values: they may contain TOTP secrets.
#[derive(Debug, Error)]
pub enum Error {
    #[error("{0}")]
    Invalid(&'static str),
    #[error("invalid JSON at line {line}, column {column}")]
    Json { line: usize, column: usize },
    #[error("entry {index}: {source}")]
    Entry {
        index: usize,
        #[source]
        source: Box<Error>,
    },
    #[error("line {line}: {source}")]
    Line {
        line: usize,
        #[source]
        source: Box<Error>,
    },
    #[error(
        "incomplete Google migration batch: received {received} of {expected} QR codes; supply every part together"
    )]
    IncompleteBatch { received: usize, expected: usize },
    #[error("wrong password or damaged encrypted bundle")]
    Decryption,
    #[error("file operation failed: {0}")]
    Io(#[from] std::io::Error),
}

impl Error {
    pub(crate) fn entry(self, index: usize) -> Self {
        Self::Entry {
            index,
            source: Box::new(self),
        }
    }

    pub(crate) fn line(self, line: usize) -> Self {
        Self::Line {
            line,
            source: Box::new(self),
        }
    }
}

impl From<serde_json::Error> for Error {
    fn from(value: serde_json::Error) -> Self {
        Self::Json {
            line: value.line(),
            column: value.column(),
        }
    }
}

pub type Result<T> = std::result::Result<T, Error>;
