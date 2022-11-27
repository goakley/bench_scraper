#![warn(missing_docs)]
#[derive(Debug)]
#[non_exhaustive]
/// Enum listing possible errors from bench scraper operations.
pub enum Error {
    #[cfg(target_os = "linux")]
    /// An error that originated from the Linux Secret Service API (used for managing cookie encryption keys).
    SecretServiceError(secret_service::Error),
    #[cfg(target_os = "windows")]
    /// An error that originated from the Windows Data Protection API (used for managing cookie encryption keys).
    DPAPIError(&'static str),
    /// An error that occurred while decrypting a secret.
    PasswordHashError(pbkdf2::password_hash::errors::Error),
    /// A failure while working with the filesystem.
    IOError(std::io::Error),
    /// A failure while working with SQLite-backed cookie storage.
    SQLError(rusqlite::Error),
    /// A failure while parsing binary cookie data.
    BinaryError(nom::error::Error<Vec<u8>>),
}

impl From<pbkdf2::password_hash::errors::Error> for Error {
    fn from(err: pbkdf2::password_hash::errors::Error) -> Self {
        Error::PasswordHashError(err)
    }
}

#[cfg(target_os = "linux")]
impl From<secret_service::Error> for Error {
    fn from(err: secret_service::Error) -> Self {
        Error::SecretServiceError(err)
    }
}

impl From<std::io::Error> for Error {
    fn from(err: std::io::Error) -> Self {
        Error::IOError(err)
    }
}

impl From<rusqlite::Error> for Error {
    fn from(err: rusqlite::Error) -> Self {
        Error::SQLError(err)
    }
}

impl From<nom::error::Error<&[u8]>> for Error {
    fn from(err: nom::error::Error<&[u8]>) -> Self {
        Error::BinaryError(nom::error::Error {
            input: err.input.to_vec(),
            code: err.code,
        })
    }
}
