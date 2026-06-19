use thiserror::Error;

use crate::{config::DatabaseVersion, db::Database, DatabaseKey, TransformedKey};

impl Database {
    /// Saves the database to the given destination, using the provided key for encryption.
    pub fn save(
        &self,
        destination: &mut dyn std::io::Write,
        key: DatabaseKey,
    ) -> Result<(), DatabaseSaveError> {
        use crate::format::kdbx4::dump_kdbx4;

        match self.config.version {
            DatabaseVersion::KDB(_) => Err(DatabaseSaveError::UnsupportedVersion),
            DatabaseVersion::KDB2(_) => Err(DatabaseSaveError::UnsupportedVersion),
            DatabaseVersion::KDB3(_) => Err(DatabaseSaveError::UnsupportedVersion),
            DatabaseVersion::KDB4(_) => dump_kdbx4(self, &key, destination),
        }
    }

    /// Like [`Database::save`], but return the post-KDF transformed key derived
    /// under the freshly-rotated KDF seed, so a caller can re-cache it for a
    /// fast re-open of the just-saved file. KDBX4 only.
    pub fn save_capturing_key(
        &self,
        destination: &mut dyn std::io::Write,
        key: DatabaseKey,
    ) -> Result<TransformedKey, DatabaseSaveError> {
        use crate::format::kdbx4::dump_kdbx4_capturing;

        match self.config.version {
            DatabaseVersion::KDB(_) => Err(DatabaseSaveError::UnsupportedVersion),
            DatabaseVersion::KDB2(_) => Err(DatabaseSaveError::UnsupportedVersion),
            DatabaseVersion::KDB3(_) => Err(DatabaseSaveError::UnsupportedVersion),
            DatabaseVersion::KDB4(_) => {
                let transformed = dump_kdbx4_capturing(self, &key, destination)?;
                Ok(TransformedKey::from_bytes(*transformed)?)
            }
        }
    }
}

/// Errors that can occur during saving of the database to a KDBX file
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum DatabaseSaveError {
    /// I/O errors that can occur while writing the database to the destination, such as file system errors
    #[error(transparent)]
    Io(#[from] std::io::Error),

    /// Errors related to XML serialization of the database
    #[error(transparent)]
    Serialization(#[from] quick_xml::SeError),

    /// Errors related to database key operations
    #[error(transparent)]
    Key(#[from] crate::key::DatabaseKeyError),

    /// Errors related to encryption operations
    #[error(transparent)]
    Cryptography(#[from] crate::crypt::CryptographyError),

    /// Errors related to random number generation
    #[error(transparent)]
    Random(#[from] getrandom::Error),

    /// Secure-memory allocation for the captured transformed key failed
    #[error(transparent)]
    SecureMemory(#[from] shrouded::ShroudError),

    /// Attempted to save a database with an unsupported version (e.g., KDB, KDBX2, or KDBX3)
    #[error("Unsupported database version")]
    UnsupportedVersion,
}
