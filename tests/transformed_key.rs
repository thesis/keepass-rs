//! Capture/supply transformed-key entry points (fork addition).
//!
//! Verifies the fast-open path round-trips, that a wrong transformed key fails
//! the header HMAC (and never decrypts), that save returns a usable key, and
//! that the key is bound to the per-save KDF salt.
#![cfg(feature = "save_kdbx4")]

use keepass::{Database, DatabaseKey, TransformedKey};

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
fn save_capturing_key_returns_usable_key() {
    let mut db = Database::new();
    db.root_mut().add_entry();

    let mut bytes = Vec::new();
    let captured = db.save_capturing_key(&mut bytes, key()).unwrap();

    let mut reader = bytes.as_slice();
    let reopened = Database::open_with_transformed_key(&mut reader, &captured).unwrap();
    assert_eq!(reopened.num_entries(), 1);
}

#[test]
fn transformed_key_is_bound_to_the_rotating_salt() {
    // The KDF salt rotates on every save, so a key derived for one on-disk
    // state must not open a later re-saved state.
    let mut db = Database::new();
    db.root_mut().add_entry();

    let mut bytes1 = Vec::new();
    let key1 = db.save_capturing_key(&mut bytes1, key()).unwrap();

    let mut bytes2 = Vec::new();
    let key2 = db.save_capturing_key(&mut bytes2, key()).unwrap();

    assert_ne!(
        key1.as_bytes(),
        key2.as_bytes(),
        "salt rotation should change the transformed key"
    );

    // key1 belongs to bytes1's salt; it must not open bytes2 ...
    let mut reader = bytes2.as_slice();
    assert!(
        Database::open_with_transformed_key(&mut reader, &key1).is_err(),
        "key1 must not open a file saved under a different salt"
    );

    // ... but it still opens its own file.
    let mut reader = bytes1.as_slice();
    assert!(
        Database::open_with_transformed_key(&mut reader, &key1).is_ok(),
        "key1 must still open its own file"
    );
}
