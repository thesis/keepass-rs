use std::io::Write;

use byteorder::{LittleEndian, WriteBytesExt};
use zeroize::Zeroizing;

use crate::{
    crypt,
    db::{Database, DatabaseSaveError, Value},
    format::{
        hmac_block_stream,
        io::WriteLengthTaggedExt,
        kdbx4::{
            KDBX4InnerHeader, KDBX4OuterHeader, HEADER_COMPRESSION_ID, HEADER_ENCRYPTION_IV, HEADER_END,
            HEADER_KDF_PARAMS, HEADER_MASTER_SEED, HEADER_MASTER_SEED_SIZE, HEADER_OUTER_ENCRYPTION_ID,
            INNER_HEADER_BINARY_ATTACHMENTS, INNER_HEADER_END, INNER_HEADER_RANDOM_STREAM_ID,
            INNER_HEADER_RANDOM_STREAM_KEY,
        },
        variant_dictionary::VariantDictionary,
        DatabaseVersion,
    },
    key::DatabaseKey,
};

use super::HEADER_PUBLIC_CUSTOM_DATA;

/// How the KDBX4 transformed key is obtained when saving.
pub(crate) enum Kdbx4DumpKeySource<'a> {
    /// Derive it by running the (expensive) KDF over the composite key.
    Derive(&'a DatabaseKey),
    /// Reuse a previously-captured transformed key, skipping the KDF entirely.
    /// Only sound together with the same KDF seed the key was derived under.
    Reuse(&'a [u8; 32]),
}

/// Dump a KeePass database using the key elements
pub fn dump_kdbx4(
    db: &Database,
    db_key: &DatabaseKey,
    writer: &mut dyn Write,
) -> Result<(), DatabaseSaveError> {
    dump_kdbx4_capturing(db, db_key, writer).map(|_key_and_seed| ())
}

/// Like [`dump_kdbx4`], but return the post-KDF transformed key and the fresh
/// KDF seed it was derived under, so a caller can re-cache the pair — for a
/// fast re-open of the just-saved file, and for a fast later save via
/// [`dump_kdbx4_with_transformed_key`].
///
/// The seed is not a secret (it is written unencrypted into the outer header
/// this function just dumped); it is returned so the caller can pair it with
/// the key.
pub fn dump_kdbx4_capturing(
    db: &Database,
    db_key: &DatabaseKey,
    writer: &mut dyn Write,
) -> Result<(Zeroizing<[u8; 32]>, Vec<u8>), DatabaseSaveError> {
    let kdf_seed = db.config.kdf_config.random_seed()?;
    let key = dump_kdbx4_inner(db, &kdf_seed, Kdbx4DumpKeySource::Derive(db_key), writer)?;
    Ok((key, kdf_seed))
}

/// Dump a KeePass database reusing a previously-captured KDF seed and
/// transformed key, skipping the KDF entirely.
///
/// The pair must come from a prior capturing dump of this same database under
/// still-current credentials and an unchanged KDF config — otherwise the
/// written file cannot be opened with the real credentials. Per-save
/// ciphertext freshness is unaffected: the master seed, outer IV, and inner
/// stream key are still regenerated on every dump.
pub fn dump_kdbx4_with_transformed_key(
    db: &Database,
    kdf_seed: &[u8],
    transformed_key: &[u8; 32],
    writer: &mut dyn Write,
) -> Result<(), DatabaseSaveError> {
    let expected = db.config.kdf_config.seed_size();
    if kdf_seed.len() != expected {
        return Err(DatabaseSaveError::InvalidKdfSeed {
            expected,
            actual: kdf_seed.len(),
        });
    }

    dump_kdbx4_inner(db, kdf_seed, Kdbx4DumpKeySource::Reuse(transformed_key), writer).map(|_key| ())
}

/// Shared dump body: write the database under the given KDF seed, obtaining
/// the transformed key per `key_source`. Fresh per-save randomness (master
/// seed, outer IV, inner stream key) is generated here, on every path.
fn dump_kdbx4_inner(
    db: &Database,
    kdf_seed: &[u8],
    key_source: Kdbx4DumpKeySource<'_>,
    writer: &mut dyn Write,
) -> Result<Zeroizing<[u8; 32]>, DatabaseSaveError> {
    if !matches!(db.config.version, DatabaseVersion::KDB4(1)) {
        return Err(DatabaseSaveError::UnsupportedVersion);
    }

    // generate encryption keys and seeds on the fly when saving
    let mut master_seed = vec![0; HEADER_MASTER_SEED_SIZE];
    getrandom::fill(&mut master_seed)?;

    let mut outer_iv = vec![0; db.config.outer_cipher_config.get_iv_size()];
    getrandom::fill(&mut outer_iv)?;

    let mut inner_random_stream_key = vec![0; db.config.inner_cipher_config.get_key_size()];
    getrandom::fill(&mut inner_random_stream_key)?;

    // dump the outer header - need to buffer so that SHA256 can be computed
    let mut header_data = Vec::new();

    db.config.version.dump(&mut header_data)?;

    KDBX4OuterHeader {
        outer_cipher_config: db.config.outer_cipher_config.clone(),
        compression_config: db.config.compression_config.clone(),
        master_seed: master_seed.clone(),
        outer_iv: outer_iv.clone(),
        kdf_config: db.config.kdf_config.clone(),
        kdf_seed: kdf_seed.to_vec(),
        public_custom_data: db.config.public_custom_data.clone(),
    }
    .dump(&mut header_data)?;

    let header_sha256 = crypt::calculate_sha256(&[&header_data]);

    // write out header and header hash
    writer.write_all(&header_data)?;
    writer.write_all(&header_sha256)?;

    // obtain the 32-byte transformed key — by running the KDF (the expensive
    // step) or from a previously-captured value.
    let transformed_key: Zeroizing<[u8; 32]> = match key_source {
        Kdbx4DumpKeySource::Derive(db_key) => {
            #[cfg(feature = "challenge_response")]
            let db_key = db_key.clone().perform_challenge(kdf_seed)?;

            // derive master key from composite key, transform_seed, transform_rounds and master_seed
            let key_elements = db_key.get_key_elements()?;
            let key_elements: Vec<&[u8]> = key_elements.iter().map(|v| &v[..]).collect();
            let composite_key = crypt::calculate_sha256(&key_elements);
            let derived = db
                .config
                .kdf_config
                .get_kdf_seeded(kdf_seed)
                .transform_key(&composite_key)?;
            let mut bytes = Zeroizing::new([0u8; 32]);
            bytes.copy_from_slice(derived.as_ref());
            bytes
        }
        // Reuse skips the challenge-response step too: the challenge input is
        // the KDF seed, and a reused key was captured under this same seed, so
        // it already embodies the response.
        Kdbx4DumpKeySource::Reuse(tk) => Zeroizing::new(*tk),
    };

    let master_key = crypt::calculate_sha256(&[&master_seed, transformed_key.as_slice()]);

    // verify credentials
    let hmac_key = crypt::calculate_sha512(&[
        &master_seed,
        transformed_key.as_slice(),
        &hmac_block_stream::HMAC_KEY_END,
    ]);
    let header_hmac_key = hmac_block_stream::get_hmac_block_key(u64::MAX, &hmac_key);

    #[allow(clippy::expect_used)] // HMAC key is always correctly sized, so this can't fail
    let header_hmac =
        crypt::calculate_hmac(&[&header_data], &header_hmac_key).expect("HMAC key always correctly sized");

    writer.write_all(&header_hmac)?;

    // Initialize inner encryptor from inner header params
    let mut inner_cipher = db
        .config
        .inner_cipher_config
        .get_cipher(&inner_random_stream_key)?;

    // convert database to XML and header attachments
    let (xml, attachments) = crate::format::xml_db::to_xml(db, &mut *inner_cipher)?;

    // dump inner header into buffer
    let mut payload = Vec::new();
    KDBX4InnerHeader {
        inner_random_stream: db.config.inner_cipher_config.clone(),
        inner_random_stream_key,
    }
    .dump(&attachments, &mut payload)?;

    payload.extend(xml);

    let payload_compressed = db
        .config
        .compression_config
        .get_compression()
        .compress(&payload)?;

    let payload_encrypted = db
        .config
        .outer_cipher_config
        .get_cipher(&master_key, &outer_iv)?
        .encrypt(&payload_compressed)?;

    let payload_hmac = hmac_block_stream::write_hmac_block_stream(&payload_encrypted, &hmac_key);
    writer.write_all(&payload_hmac)?;

    Ok(transformed_key)
}

impl KDBX4OuterHeader {
    fn dump(&self, writer: &mut dyn Write) -> Result<(), DatabaseSaveError> {
        writer.write_u8(HEADER_OUTER_ENCRYPTION_ID)?;
        writer.write_with_len(&self.outer_cipher_config.dump())?;

        writer.write_u8(HEADER_COMPRESSION_ID)?;
        writer.write_with_len(&self.compression_config.dump())?;

        writer.write_u8(HEADER_ENCRYPTION_IV)?;
        writer.write_with_len(&self.outer_iv)?;

        writer.write_u8(HEADER_MASTER_SEED)?;
        writer.write_with_len(&self.master_seed)?;

        let vd: VariantDictionary = self.kdf_config.to_variant_dictionary(&self.kdf_seed);
        let mut vd_buffer = Vec::new();
        vd.dump(&mut vd_buffer)?;

        writer.write_u8(HEADER_KDF_PARAMS)?;
        writer.write_with_len(&vd_buffer)?;

        if let Some(pcd) = &self.public_custom_data {
            let mut vd_buffer = Vec::new();
            pcd.dump(&mut vd_buffer)?;

            writer.write_u8(HEADER_PUBLIC_CUSTOM_DATA)?;
            writer.write_with_len(&vd_buffer)?;
        }

        writer.write_u8(HEADER_END)?;
        writer.write_with_len(&[])?;

        Ok(())
    }
}

impl KDBX4InnerHeader {
    fn dump(
        &self,
        header_attachments: &[Value<Vec<u8>>],
        writer: &mut dyn Write,
    ) -> Result<(), DatabaseSaveError> {
        writer.write_all(&[INNER_HEADER_RANDOM_STREAM_ID])?;
        writer.write_u32::<LittleEndian>(4)?;
        writer.write_u32::<LittleEndian>(self.inner_random_stream.dump())?;

        writer.write_u8(INNER_HEADER_RANDOM_STREAM_KEY)?;
        writer.write_with_len(&self.inner_random_stream_key)?;

        for attachment in header_attachments {
            writer.write_u8(INNER_HEADER_BINARY_ATTACHMENTS)?;
            writer.write_u32::<LittleEndian>((attachment.len() + 1) as u32)?;
            writer.write_u8(if attachment.is_protected() { 0x01 } else { 0x00 })?;
            writer.write_all(attachment.get())?;
        }

        writer.write_u8(INNER_HEADER_END)?;
        writer.write_with_len(&[])?;

        Ok(())
    }
}
