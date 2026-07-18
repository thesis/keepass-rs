//! The post-KDF transformed key.
//!
//! Added on the `transformed-key` branch (a downstream fork addition). KDBX
//! decryption has two stages: the expensive KDF (Argon2id / AES-KDF) that turns
//! the composite key into a 32-byte *transformed key*, and the cheap step that
//! combines that with the per-save master seed to make the actual decryption
//! key. Exposing the transformed key lets a caller cache it and skip the KDF on
//! a later open of the same on-disk database state — and, together with the KDF
//! seed a save minted (see [`CapturedKdf`]), on a later save too.

use shrouded::{Expose, ShroudError, ShroudedArray};
use zeroize::Zeroizing;

use crate::config::KdfConfig;

/// The 32-byte post-KDF transformed key, before it is combined with the
/// per-save master seed. This is the expensive Argon2id / AES-KDF output.
///
/// Holding it is equivalent in power to holding the composite key (password +
/// keyfile) for one specific on-disk state, so it is treated as a secret: the
/// bytes live in `shrouded` secure memory (mlock'd, guard-paged, excluded from
/// core dumps via `MADV_DONTDUMP`, zeroized on drop). There is deliberately no
/// `Clone` and no `Display`.
pub struct TransformedKey(ShroudedArray<32>);

impl TransformedKey {
    /// Wrap raw transformed-key bytes (e.g. read back from a cache). `bytes` is
    /// zeroized as it moves into secure memory.
    pub fn from_bytes(bytes: [u8; 32]) -> Result<Self, ShroudError> {
        Ok(Self(ShroudedArray::from_array(bytes)?))
    }

    /// The raw 32 transformed-key bytes.
    pub fn as_bytes(&self) -> &[u8; 32] {
        self.0.expose()
    }
}

/// The KDF material a save minted: the fresh seed it wrote into the file
/// header, the transformed key derived under that seed, and the KDF
/// parameters both belong to.
///
/// Returned by [`crate::Database::save_capturing_key`] so a caller can pass
/// the pair to [`crate::Database::save_with_transformed_key`] and skip the
/// KDF on a later save of the same database. Reuse is sound only while the
/// database's credentials and KDF parameters are unchanged — carry the
/// [`KdfConfig`] along and compare it before reusing.
///
/// The seed is not a secret: it is written unencrypted into the KDBX outer
/// header. It is held in [`Zeroizing`] memory as uniform hygiene, not in
/// `shrouded` secure memory; the transformed key inside stays shrouded.
pub struct CapturedKdf {
    key: TransformedKey,
    kdf_seed: Zeroizing<Vec<u8>>,
    kdf_config: KdfConfig,
}

impl CapturedKdf {
    /// Assemble a bundle from its parts (e.g. rebuilding cache state).
    ///
    /// The caller is responsible for the parts belonging together: a seed,
    /// key, and config that were not produced by the same save will make
    /// [`crate::Database::save_with_transformed_key`] write a file the real
    /// credentials cannot open.
    pub fn from_parts(key: TransformedKey, kdf_seed: Vec<u8>, kdf_config: KdfConfig) -> Self {
        Self {
            key,
            kdf_seed: Zeroizing::new(kdf_seed),
            kdf_config,
        }
    }

    /// The transformed key derived under [`Self::kdf_seed`].
    pub fn key(&self) -> &TransformedKey {
        &self.key
    }

    /// The KDF seed the save wrote into the file header.
    pub fn kdf_seed(&self) -> &[u8] {
        &self.kdf_seed
    }

    /// The KDF parameters the seed and key were minted under.
    pub fn kdf_config(&self) -> &KdfConfig {
        &self.kdf_config
    }

    /// Decompose into parts (e.g. for storage in a caller-side cache).
    pub fn into_parts(self) -> (TransformedKey, Zeroizing<Vec<u8>>, KdfConfig) {
        (self.key, self.kdf_seed, self.kdf_config)
    }
}
