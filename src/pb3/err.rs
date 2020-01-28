use std::error;
use std::fmt;
use std::result;

/// Errors occuring during unwrapping. Any error indicates message compromise.
/// Error codes should only be treated as indication of internal check failure.
#[derive(PartialEq, Eq, Copy, Clone, Debug)]
pub enum Err {
    /// Bad `oneof` value.
    BadOneOf,

    /// Bad value (usually, integral).
    BadValue,

    /// End of input buffer.
    Eof,

    /// Internal error.
    InternalError,

    /// Key not found.
    KeyNotFound,

    /// Link not found.
    LinkNotFound,

    /// MAC verification failed.
    MacVerifyFailed,

    /// MSS signature verification failed.
    MssVerifyFailed,

    /// NTRU invalid/corrupted public key.
    NtruBadPublicKey,

    /// NTRU key decapsulation failed.
    NtruDecrFailed,

    /// Message version unsupported.
    VersionUnsupported,
}

fn err_str(e: Err) -> &'static str {
    match e {
        Err::BadOneOf => "Bad `oneof` value.",
        Err::BadValue => "Bad value (usually, integral).",
        Err::Eof => "End of input buffer.",
        Err::InternalError => "Internal error.",
        Err::KeyNotFound => "Key not found.",
        Err::LinkNotFound => "Link not found.",
        Err::MacVerifyFailed => "MAC verification failed.",
        Err::MssVerifyFailed => "MSS signature verification failed.",
        Err::NtruDecrFailed => "NTRU key decapsulation failed.",
        Err::NtruBadPublicKey => "NTRU invalid/corrupted public key.",
        Err::VersionUnsupported => "Message version unsupported.",
    }
}

impl fmt::Display for Err {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", err_str(*self))
    }
}

impl error::Error for Err {
    fn description(&self) -> &str {
        err_str(*self)
    }
}

/// Result type customized for PB3 error type.
pub type Result<T> = result::Result<T, Err>;

/// Guard code for condition and return error in case the condition is not met.
///
/// # Arguments
///
/// * `condition` -- guard condition.
///
/// * `e` -- error to be returned in case of `false` `condition`.
///
/// # Example
///
/// ```
/// extern crate iota_mam;
/// use iota_mam::pb3::err::{Err, guard};
/// fn div(a: u32, b: u32) -> Result<u32, Err> {
///     guard(b != 0, Err::BadValue)?;
///     Ok(a / b)
/// }
/// let undefined = div(1, 0);
/// assert!(undefined.is_err());
/// ```
#[inline]
pub fn guard(condition: bool, e: Err) -> Result<()> {
    if condition {
        Ok(())
    } else {
        Err(e)
    }
}
