use std::{fmt, io};

/// A human-friendly format string for the `UTCStamp`.
pub const FORMAT_STRING: &str = "%Y-%m-%dT%H:%M:%S";

/// 2023-11-15 00:00 UTC - a supposedly significant date.
const INCEPTION_SECS: i64 = 0b1110_1000_1111_1110_1000_1000_1000_0000;
/// NTP Epoch, which is different from UNIX Epoch. Because time is retrieved
/// from NTP, `NTP_EPOCH` is used for conversion.
const NTP_EPOCH: chrono::NaiveDateTime = match chrono::NaiveDate::from_ymd_opt(1900, 1, 1) {
    Some(d) => d.and_time(chrono::NaiveTime::MIN),
    None => unreachable!(),
};

/// A timestamp in UTC seconds relative to 2023-11-15T00:00:00. Used wherever
/// the date and time are expected to be stored.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct UTCStamp(pub i64);

impl UTCStamp {
    /// Retrieves a [`UTCStamp`] from an NTP server at `address`.
    ///
    /// # Errors
    ///
    /// An IO error is returned if NTP request fails for any reason. For NTP-specific
    /// errors and error of [`io::ErrorKind::Other`] is returned.
    pub fn retrieve(address: &str) -> Result<UTCStamp, io::Error> {
        let response = ntp::request(address).map_err(|err| match err.kind() {
            ntp::errors::ErrorKind::IOError(ioerr) => {
                io::Error::new(ioerr.kind(), err.description())
            }
            ntp::errors::ErrorKind::Msg(msg) => io::Error::other(String::from(msg)),
            ntp::errors::ErrorKind::UnrepresentableU8(_)
            | ntp::errors::ErrorKind::UnrepresentableU32(_) => {
                io::Error::other("value conversion failed while retrieving timestamp")
            }
            _ => io::Error::other("unknown error while retrieving timestamp"),
        })?;
        Ok(response.transmit_time.into())
    }
}

impl From<ntp::formats::timestamp::TimestampFormat> for UTCStamp {
    fn from(value: ntp::formats::timestamp::TimestampFormat) -> UTCStamp {
        let secs = i64::from(value.sec).wrapping_sub(INCEPTION_SECS);
        UTCStamp(secs)
    }
}

impl From<chrono::DateTime<chrono::Utc>> for UTCStamp {
    fn from(value: chrono::DateTime<chrono::Utc>) -> UTCStamp {
        (&value).into()
    }
}

impl From<&chrono::DateTime<chrono::Utc>> for UTCStamp {
    fn from(value: &chrono::DateTime<chrono::Utc>) -> UTCStamp {
        let secs = value
            .checked_add_signed(chrono::NaiveDateTime::UNIX_EPOCH - NTP_EPOCH)
            .expect("DateTime supposed to be within a range")
            .timestamp()
            .wrapping_sub(INCEPTION_SECS);
        UTCStamp(secs)
    }
}

impl fmt::Display for UTCStamp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let secs = self.0.wrapping_add(INCEPTION_SECS);
        let datetime = chrono::DateTime::from_timestamp(secs, 0)
            .expect("UTCStamp supposed to fit into DateTime type")
            .checked_sub_signed(chrono::NaiveDateTime::UNIX_EPOCH - NTP_EPOCH)
            .expect("DateTime supposed to be within a range");
        write!(f, "{}", datetime.format(FORMAT_STRING))
    }
}

#[cfg(test)]
mod tests {
    use ntp::formats::timestamp::TimestampFormat;

    use super::*;

    #[test]
    fn from_timestamp_format() {
        let inception_secs = INCEPTION_SECS as u32;

        let case = "greater than inception";
        let ts = TimestampFormat {
            sec: inception_secs + 4,
            frac: 0b0111,
        };
        assert_eq!(
            <TimestampFormat as Into<UTCStamp>>::into(ts),
            UTCStamp(4),
            "{case}",
        );

        let case = "smaller than inception";
        let ts = TimestampFormat {
            sec: inception_secs - 2,
            frac: 0b1001,
        };
        assert_eq!(
            <TimestampFormat as Into<UTCStamp>>::into(ts),
            UTCStamp(-2),
            "{case}",
        );

        let case = "equal to inception";
        let ts = TimestampFormat {
            sec: inception_secs,
            frac: 0b110001,
        };
        assert_eq!(
            <TimestampFormat as Into<UTCStamp>>::into(ts),
            UTCStamp(0),
            "{case}",
        );
    }

    #[test]
    fn from_chrono_datetime() {
        let case = "greater than inception";
        let datetime = chrono::NaiveDate::from_ymd_opt(2023, 11, 17)
            .unwrap()
            .and_time(chrono::NaiveTime::MIN)
            .and_utc();

        assert_eq!(
            <&chrono::DateTime<chrono::Utc> as Into<UTCStamp>>::into(&datetime),
            UTCStamp(0b0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0010_1010_0011_0000_0000i64),
            "{case}",
        );

        let case = "smaller than inception";
        let datetime = chrono::NaiveDate::from_ymd_opt(2023, 11, 13)
            .unwrap()
            .and_time(chrono::NaiveTime::MIN)
            .and_utc();
        assert_eq!(
            <&chrono::DateTime<chrono::Utc> as Into<UTCStamp>>::into(&datetime),
            UTCStamp(
                0b1111_1111_1111_1111_1111_1111_1111_1111_1111_1111_1111_1101_0101_1101_0000_0000u64
                    as i64,
            ),
            "{case}",
        );

        let case = "equal to inception";
        let datetime = chrono::NaiveDate::from_ymd_opt(2023, 11, 15)
            .unwrap()
            .and_time(chrono::NaiveTime::MIN)
            .and_utc();
        assert_eq!(
            <&chrono::DateTime<chrono::Utc> as Into<UTCStamp>>::into(&datetime),
            UTCStamp(0),
            "{case}",
        );
    }
}
