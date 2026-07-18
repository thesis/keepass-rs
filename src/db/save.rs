use thiserror::Error;

use crate::{config::DatabaseVersion, db::Database, CapturedKdf, DatabaseKey, TransformedKey};

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

    /// Like [`Database::save`], but return the KDF material the save minted —
    /// the fresh KDF seed, the post-KDF transformed key derived under it, and
    /// the KDF config both belong to — so a caller can re-cache it for a fast
    /// re-open of the just-saved file and a fast later save via
    /// [`Database::save_with_transformed_key`]. KDBX4 only.
    pub fn save_capturing_key(
        &self,
        destination: &mut dyn std::io::Write,
        key: DatabaseKey,
    ) -> Result<CapturedKdf, DatabaseSaveError> {
        use crate::format::kdbx4::dump_kdbx4_capturing;

        match self.config.version {
            DatabaseVersion::KDB(_) => Err(DatabaseSaveError::UnsupportedVersion),
            DatabaseVersion::KDB2(_) => Err(DatabaseSaveError::UnsupportedVersion),
            DatabaseVersion::KDB3(_) => Err(DatabaseSaveError::UnsupportedVersion),
            DatabaseVersion::KDB4(_) => {
                let (transformed, kdf_seed) = dump_kdbx4_capturing(self, &key, destination)?;
                Ok(CapturedKdf::from_parts(
                    TransformedKey::from_bytes(*transformed)?,
                    kdf_seed,
                    self.config.kdf_config.clone(),
                ))
            }
        }
    }

    /// Save the database reusing a previously-captured KDF seed and
    /// transformed key, skipping the expensive KDF entirely. KDBX4 only.
    ///
    /// Contract: `kdf_seed` and `transformed_key` must come from a prior
    /// [`Database::save_capturing_key`] of this same database, under
    /// credentials that are still current and with a KDF config equal to
    /// `self.config.kdf_config` — violating this writes a file the real
    /// credentials cannot open. Per-save ciphertext freshness is unaffected:
    /// the master seed, outer IV, and inner stream key are still regenerated
    /// on every save.
    pub fn save_with_transformed_key(
        &self,
        destination: &mut dyn std::io::Write,
        kdf_seed: &[u8],
        transformed_key: &TransformedKey,
    ) -> Result<(), DatabaseSaveError> {
        use crate::format::kdbx4::dump_kdbx4_with_transformed_key;

        match self.config.version {
            DatabaseVersion::KDB(_) => Err(DatabaseSaveError::UnsupportedVersion),
            DatabaseVersion::KDB2(_) => Err(DatabaseSaveError::UnsupportedVersion),
            DatabaseVersion::KDB3(_) => Err(DatabaseSaveError::UnsupportedVersion),
            DatabaseVersion::KDB4(_) => {
                dump_kdbx4_with_transformed_key(self, kdf_seed, transformed_key.as_bytes(), destination)
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

    /// A reused KDF seed does not match the size the configured KDF expects
    #[error("KDF seed length {actual} does not match the configured KDF (expected {expected})")]
    InvalidKdfSeed {
        /// The seed size the configured KDF expects
        expected: usize,
        /// The length of the seed that was supplied
        actual: usize,
    },

    /// Attempted to save a database with an unsupported version (e.g., KDB, KDBX2, or KDBX3)
    #[error("Unsupported database version")]
    UnsupportedVersion,
}
