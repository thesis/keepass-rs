//! Capture/supply transformed-key entry points (fork addition).
//!
//! Verifies the fast-open path round-trips, that a wrong transformed key fails
//! the header HMAC (and never decrypts), that save returns a usable key+seed
//! bundle, that the key is bound to the KDF salt, and that the reused-seed
//! fast save produces files openable both by credentials and by the cached
//! key while still rotating the per-save ciphertext material.
#![cfg(feature = "save_kdbx4")]

use keepass::{CapturedKdf, Database, DatabaseKey, TransformedKey};

fn key() -> DatabaseKey {
    DatabaseKey::new().with_password("correct horse battery staple")
}

/// A freshly-saved KDBX4 database with `entries` empty entries.
fn saved_db(entries: usize) -> Vec<u8> {
    let mut db = Database::new();
    for _ in 0..entries {
        db.root_mut().add_entry();
    }
    let mut bytes = Vec::new();
    db.save(&mut bytes, key()).unwrap();
    bytes
}

#[test]
fn capture_then_open_with_key_roundtrips() {
    let bytes = saved_db(2);

    // A normal open that also hands back the transformed key.
    let mut reader = bytes.as_slice();
    let (db, captured) = Database::open_capturing_key(&mut reader, key()).unwrap();
    assert_eq!(db.num_entries(), 2);
    let captured = captured.expect("KDBX4 open should capture a transformed key");

    // Re-opening with the captured key (no KDF) yields the same database.
    let mut reader = bytes.as_slice();
    let db2 = Database::open_with_transformed_key(&mut reader, &captured).unwrap();
    assert_eq!(db2.num_entries(), 2);
}

#[test]
fn wrong_transformed_key_fails_hmac() {
    let bytes = saved_db(1);
    let bogus = TransformedKey::from_bytes([0x11; 32]).unwrap();

    let mut reader = bytes.as_slice();
    assert!(
        Database::open_with_transformed_key(&mut reader, &bogus).is_err(),
        "a wrong transformed key must fail the HMAC, not decrypt"
    );
}

#[test]
fn save_capturing_key_returns_usable_bundle() {
    let mut db = Database::new();
    db.root_mut().add_entry();

    let mut bytes = Vec::new();
    let captured = db.save_capturing_key(&mut bytes, key()).unwrap();
    assert_eq!(captured.kdf_config(), &db.config.kdf_config);

    let mut reader = bytes.as_slice();
    let reopened = Database::open_with_transformed_key(&mut reader, captured.key()).unwrap();
    assert_eq!(reopened.num_entries(), 1);
}

#[test]
fn transformed_key_is_bound_to_the_rotating_salt() {
    // The KDF salt rotates on every capturing save, so a key derived for one
    // on-disk state must not open a later re-saved state.
    let mut db = Database::new();
    db.root_mut().add_entry();

    let mut bytes1 = Vec::new();
    let captured1 = db.save_capturing_key(&mut bytes1, key()).unwrap();

    let mut bytes2 = Vec::new();
    let captured2 = db.save_capturing_key(&mut bytes2, key()).unwrap();

    assert_ne!(
        captured1.kdf_seed(),
        captured2.kdf_seed(),
        "each capturing save should mint a fresh salt"
    );
    assert_ne!(
        captured1.key().as_bytes(),
        captured2.key().as_bytes(),
        "salt rotation should change the transformed key"
    );

    // captured1 belongs to bytes1's salt; it must not open bytes2 ...
    let mut reader = bytes2.as_slice();
    assert!(
        Database::open_with_transformed_key(&mut reader, captured1.key()).is_err(),
        "key1 must not open a file saved under a different salt"
    );

    // ... but it still opens its own file.
    let mut reader = bytes1.as_slice();
    assert!(
        Database::open_with_transformed_key(&mut reader, captured1.key()).is_ok(),
        "key1 must still open its own file"
    );
}

#[test]
fn fast_save_reused_seed_opens_with_password_and_key() {
    let mut db = Database::new();
    db.root_mut().add_entry();

    let mut bytes1 = Vec::new();
    let captured = db.save_capturing_key(&mut bytes1, key()).unwrap();

    // Mutate, then fast-save with the captured (seed, key) pair — no KDF run.
    db.root_mut().add_entry();
    let mut bytes2 = Vec::new();
    db.save_with_transformed_key(&mut bytes2, captured.kdf_seed(), captured.key())
        .unwrap();

    // The fast-saved file opens from scratch with the credentials ...
    let mut reader = bytes2.as_slice();
    let by_password = Database::open(&mut reader, key()).unwrap();
    assert_eq!(by_password.num_entries(), 2, "mutation must be present");

    // ... and with the cached key (no KDF).
    let mut reader = bytes2.as_slice();
    let by_key = Database::open_with_transformed_key(&mut reader, captured.key()).unwrap();
    assert_eq!(by_key.num_entries(), 2);
}

#[test]
fn fast_save_preserves_seed_and_key() {
    let db = Database::new();

    let mut bytes1 = Vec::new();
    let captured = db.save_capturing_key(&mut bytes1, key()).unwrap();

    let mut bytes2 = Vec::new();
    db.save_with_transformed_key(&mut bytes2, captured.kdf_seed(), captured.key())
        .unwrap();

    // A credentialed capturing open of the fast-saved file derives the same
    // transformed key — proof the on-disk salt is the one that was reused.
    let mut reader = bytes2.as_slice();
    let (_db, recaptured) = Database::open_capturing_key(&mut reader, key()).unwrap();
    let recaptured = recaptured.expect("KDBX4 open should capture a transformed key");
    assert_eq!(
        recaptured.as_bytes(),
        captured.key().as_bytes(),
        "same salt + same credentials must derive the same transformed key"
    );
}

#[test]
fn fast_save_rotates_ciphertext() {
    let db = Database::new();

    let mut bytes1 = Vec::new();
    let captured = db.save_capturing_key(&mut bytes1, key()).unwrap();

    let mut fast1 = Vec::new();
    db.save_with_transformed_key(&mut fast1, captured.kdf_seed(), captured.key())
        .unwrap();
    let mut fast2 = Vec::new();
    db.save_with_transformed_key(&mut fast2, captured.kdf_seed(), captured.key())
        .unwrap();

    // Same content, same seed, same key — but the master seed, outer IV, and
    // inner stream key are fresh per save, so the ciphertext must differ.
    assert_ne!(fast1, fast2, "per-save ciphertext freshness must be preserved");
}

#[test]
fn fast_save_rejects_wrong_length_seed() {
    let db = Database::new();

    let mut bytes = Vec::new();
    let captured = db.save_capturing_key(&mut bytes, key()).unwrap();

    let short_seed = [0u8; 16];
    let mut out = Vec::new();
    let err = db
        .save_with_transformed_key(&mut out, &short_seed, captured.key())
        .unwrap_err();
    assert!(
        matches!(
            err,
            keepass::db::DatabaseSaveError::InvalidKdfSeed {
                expected: 32,
                actual: 16
            }
        ),
        "a wrong-length seed must be rejected before writing, got: {err}"
    );
}

#[test]
fn captured_kdf_round_trips_through_parts() {
    let db = Database::new();

    let mut bytes = Vec::new();
    let captured = db.save_capturing_key(&mut bytes, key()).unwrap();

    let (tk, seed, config) = captured.into_parts();
    let rebuilt = CapturedKdf::from_parts(tk, seed.to_vec(), config);

    let mut out = Vec::new();
    db.save_with_transformed_key(&mut out, rebuilt.kdf_seed(), rebuilt.key())
        .unwrap();
    let mut reader = out.as_slice();
    assert!(Database::open(&mut reader, key()).is_ok());
}

#[cfg(feature = "challenge_response")]
#[test]
fn fast_save_with_challenge_response() {
    use keepass::ChallengeResponseKey;

    // A deterministic local challenge stands in for hardware: response =
    // HMAC-SHA1(secret, challenge), with the KDF seed as the challenge.
    let cr_key = || {
        DatabaseKey::new()
            .with_password("pw")
            .with_challenge_response_key(ChallengeResponseKey::LocalChallenge(
                "0102030405060708090a0b0c0d0e0f1011121314".to_string(),
            ))
    };

    let mut db = Database::new();
    db.root_mut().add_entry();

    let mut bytes1 = Vec::new();
    let captured = db.save_capturing_key(&mut bytes1, cr_key()).unwrap();

    // Fast save skips the challenge too: the reused key was captured under
    // this same seed, so it already embodies the response.
    db.root_mut().add_entry();
    let mut bytes2 = Vec::new();
    db.save_with_transformed_key(&mut bytes2, captured.kdf_seed(), captured.key())
        .unwrap();

    let mut reader = bytes2.as_slice();
    let reopened = Database::open(&mut reader, cr_key()).unwrap();
    assert_eq!(reopened.num_entries(), 2);
}
