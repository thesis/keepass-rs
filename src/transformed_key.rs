//! The post-KDF transformed key.
//!
//! Added on the `transformed-key` branch (a downstream fork addition). KDBX
//! decryption has two stages: the expensive KDF (Argon2id / AES-KDF) that turns
//! the composite key into a 32-byte *transformed key*, and the cheap step that
//! combines that with the per-save master seed to make the actual decryption
//! key. Exposing the transformed key lets a caller cache it and skip the KDF on
//! a later open of the same on-disk database state.

use shrouded::{Expose, ShroudError, ShroudedArray};

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
