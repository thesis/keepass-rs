use jiff::{civil::DateTime, tz::TimeZone};

/// Timestamps for a [Group][crate::db::Group] or [Entry][crate::db::Entry]
///
/// As the KeePass file format does not store time zone information and does not store sub-second
/// precision, all times are stored as civil [DateTime] values, in UTC, with second precision.
#[derive(Debug, PartialEq, Eq, Clone)]
#[non_exhaustive]
#[cfg_attr(feature = "serialization", derive(serde::Serialize))]
pub struct Times {
    /// The time of creation
    pub creation: Option<DateTime>,

    /// The time of the last modification
    pub last_modification: Option<DateTime>,

    /// The time of the last access
    pub last_access: Option<DateTime>,

    /// The time of expiration
    pub expiry: DateTime,

    /// The time of the last location change, which is updated when an entry is moved to a different group.
    pub location_changed: Option<DateTime>,

    /// Whether the entry or group expires.
    ///
    /// A `None` value indicates that the expiration status is not set
    pub expires: Option<bool>,

    /// The number of times the entry or group has been accessed.
    pub usage_count: Option<usize>,
}

// On non-browser targets — including wasm32-wasip1 and wasm32-wasip2 —
// jiff::Timestamp::now() works (it reads std's SystemTime, which WASI 0.1+
// supports).  The `js_sys::Date::now()` path is only
// usable in true browser contexts (target_arch = "wasm32" with target_os
// = "unknown"), where wasm-bindgen post-processes the binary to resolve
// the placeholder imports.  Targeting "wasm32" alone unintentionally
// catches WASI builds and breaks linking.
#[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
fn now_timestamp() -> i64 {
    jiff::Timestamp::now().as_second()
}

#[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
fn now_timestamp() -> i64 {
    // Use JS Date.now() to get the current time in milliseconds, then convert it to seconds.
    let millis = js_sys::Date::now();
    (millis / 1000.0) as i64
}

impl Default for Times {
    /// Every timestamp unset, except `expiry`, which is the Unix epoch. jiff's own
    /// `DateTime::default()` is 0000-01-01, so `Default` is not derived.
    fn default() -> Self {
        Times {
            creation: None,
            last_modification: None,
            last_access: None,
            expiry: Times::epoch(),
            location_changed: None,
            expires: None,
            usage_count: None,
        }
    }
}

impl Times {
    /// Returns the current time, without the nanoseconds since the last leap second.
    #[allow(clippy::unwrap_used, clippy::missing_panics_doc)] // current time should always be valid
    pub fn now() -> DateTime {
        let now = jiff::Timestamp::from_second(now_timestamp()).unwrap();
        TimeZone::UTC.to_datetime(now)
    }

    /// Returns the epoch time (January 1, 1970, 00:00:00 UTC) as a civil `DateTime`.
    pub fn epoch() -> DateTime {
        jiff::civil::date(1970, 1, 1).at(0, 0, 0, 0)
    }

    /// Creates a new `Times` instance with all timestamps set to the current time, `expires` set
    /// to `false`, and `usage_count` set to `0`.
    pub fn new() -> Self {
        let now = Times::now();
        Times {
            creation: Some(now),
            last_modification: Some(now),
            last_access: Some(now),
            expiry: now,
            location_changed: Some(now),
            expires: Some(false),
            usage_count: Some(0),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_expiry_is_the_unix_epoch() {
        assert_eq!(
            Times::default().expiry,
            jiff::civil::date(1970, 1, 1).at(0, 0, 0, 0)
        );
    }
}
