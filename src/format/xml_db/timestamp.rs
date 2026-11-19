use base64::{engine::general_purpose as base64_engine, Engine as _};
use jiff::{civil::DateTime, SignedDuration};
use serde::{Deserialize, Serialize, Serializer};

/// The format of an ISO 8601 timestamp in KDBX3 XML.
const ISO8601_FORMAT: &str = "%Y-%m-%dT%H:%M:%SZ";

/// In KDBX4, timestamps are stored as seconds, Base64 encoded, since 0001-01-01 00:00:00.
/// This function returns the epoch baseline used by KDBX for date serialization.
pub fn get_epoch_baseline() -> DateTime {
    jiff::civil::date(1, 1, 1).at(0, 0, 0, 0)
}

/// The KDBX4 epoch baseline plus `seconds`, saturating at the representable range.
///
/// KeePass itself cannot write a date past 9999-12-31, but a corrupt or foreign file
/// can hold any 64-bit count. Saturating keeps such a database readable.
fn from_base64_seconds(seconds: i64) -> DateTime {
    get_epoch_baseline()
        .checked_add(SignedDuration::from_secs(seconds))
        .unwrap_or(if seconds < 0 {
            DateTime::MIN
        } else {
            jiff::civil::date(9999, 12, 31).at(23, 59, 59, 0)
        })
}

#[derive(Debug, Clone, Copy)]
pub enum TimestampMode {
    Base64,
    Iso8601,
}

#[derive(Debug)]
pub struct Timestamp {
    pub mode: TimestampMode,
    pub time: DateTime,
}

impl Timestamp {
    pub fn new_base64(time: DateTime) -> Self {
        Timestamp {
            mode: TimestampMode::Base64,
            time,
        }
    }

    pub fn new_iso8601(time: DateTime) -> Self {
        Timestamp {
            mode: TimestampMode::Iso8601,
            time,
        }
    }
}

impl Default for Timestamp {
    /// The Unix epoch, 1970-01-01 00:00:00. This is the expiry a file gets when it
    /// omits `ExpiryTime`. jiff's own `DateTime::default()` is 0000-01-01, so it is
    /// not used here.
    fn default() -> Self {
        Timestamp::new_base64(crate::db::Times::epoch())
    }
}

impl From<Timestamp> for DateTime {
    fn from(t: Timestamp) -> Self {
        t.time
    }
}

impl From<DateTime> for Timestamp {
    fn from(t: DateTime) -> Self {
        // always use base64 for serialization since that seems to be most compatible with keepass
        Timestamp::new_base64(t)
    }
}

impl<'de> Deserialize<'de> for Timestamp {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let t = String::deserialize(deserializer)?;

        match DateTime::strptime(ISO8601_FORMAT, &t) {
            Ok(ndt) => Ok(Timestamp::new_iso8601(ndt)),

            // If we don't have a valid ISO 8601 string, assume we have found a Base64 encoded int.
            _ => {
                let v = base64_engine::STANDARD
                    .decode(t)
                    .map_err(serde::de::Error::custom)?;

                // Cast the decoded base64 Vec into the array expected by i64::from_le_bytes
                let mut a: [u8; 8] = [0, 0, 0, 0, 0, 0, 0, 0];
                #[allow(clippy::indexing_slicing)] // v is guaranteed to be at least 8 bytes long
                a.copy_from_slice(&v[0..8]);
                let ndt = from_base64_seconds(i64::from_le_bytes(a));

                Ok(Timestamp::new_base64(ndt))
            }
        }
    }
}

impl Serialize for Timestamp {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self.mode {
            TimestampMode::Iso8601 => {
                let s = self.time.strftime(ISO8601_FORMAT).to_string();
                serializer.serialize_str(&s)
            }
            TimestampMode::Base64 => {
                let seconds = self.time.duration_since(get_epoch_baseline()).as_secs();
                let b = seconds.to_le_bytes();
                let b64 = base64_engine::STANDARD.encode(b);
                serializer.serialize_str(&b64)
            }
        }
    }
}

#[allow(clippy::unwrap_used)]
#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Serialize, Deserialize)]
    struct Test<T>(T);

    #[test]
    fn test_deserialize_timestamp_iso8601() {
        let ts_str = "2023-10-05T12:34:56Z";
        let ts: Timestamp = quick_xml::de::from_str(ts_str).unwrap();
        assert_eq!(ts.time, "2023-10-05T12:34:56".parse::<DateTime>().unwrap());
        match ts.mode {
            TimestampMode::Iso8601 => (),
            _ => panic!("Expected Iso8601 mode"),
        }
    }

    #[test]
    fn test_deserialize_timestamp_base64() {
        let ts_str = "AQAAAAAAAAA="; // Base64 for 1 second since epoch
        let ts: Timestamp = quick_xml::de::from_str(ts_str).unwrap();
        assert_eq!(ts.time, get_epoch_baseline() + SignedDuration::from_secs(1));
        match ts.mode {
            TimestampMode::Base64 => (),
            _ => panic!("Expected Base64 mode"),
        }
    }

    #[test]
    fn test_serialize_timestamp_iso8601() {
        let ts = Timestamp {
            mode: TimestampMode::Iso8601,
            time: "2023-10-05T12:34:56".parse::<DateTime>().unwrap(),
        };
        let serialized = quick_xml::se::to_string(&Test(ts)).unwrap();
        assert_eq!(serialized, "<Test>2023-10-05T12:34:56Z</Test>");
    }

    #[test]
    fn test_serialize_timestamp_base64() {
        let ts = Timestamp {
            mode: TimestampMode::Base64,
            time: get_epoch_baseline() + SignedDuration::from_secs(1),
        };

        let serialized = quick_xml::se::to_string(&Test(ts)).unwrap();
        assert_eq!(serialized, "<Test>AQAAAAAAAAA=</Test>");
    }

    #[test]
    fn test_default_is_the_unix_epoch() {
        assert_eq!(
            Timestamp::default().time,
            jiff::civil::date(1970, 1, 1).at(0, 0, 0, 0)
        );
    }

    #[test]
    fn test_deserialize_timestamp_base64_saturates() {
        let max = base64_engine::STANDARD.encode(i64::MAX.to_le_bytes());
        let ts: Timestamp = quick_xml::de::from_str(&max).unwrap();
        assert_eq!(ts.time, jiff::civil::date(9999, 12, 31).at(23, 59, 59, 0));

        let min = base64_engine::STANDARD.encode(i64::MIN.to_le_bytes());
        let ts: Timestamp = quick_xml::de::from_str(&min).unwrap();
        assert_eq!(ts.time, DateTime::MIN);
    }

    #[test]
    fn test_base64_roundtrip_far_dates() {
        for time in [
            get_epoch_baseline(),
            jiff::civil::date(9999, 12, 31).at(23, 59, 59, 0),
            jiff::civil::date(1970, 1, 1).at(0, 0, 0, 0),
        ] {
            let serialized = quick_xml::se::to_string(&Test(Timestamp::new_base64(time))).unwrap();
            let inner = serialized
                .trim_start_matches("<Test>")
                .trim_end_matches("</Test>");
            let ts: Timestamp = quick_xml::de::from_str(inner).unwrap();
            assert_eq!(ts.time, time);
        }
    }
}
