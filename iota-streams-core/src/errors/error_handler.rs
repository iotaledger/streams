use super::error_messages::*;
use crate::{anyhow, bail, ensure};
use core::fmt::Debug;

#[macro_export]
macro_rules! try_or {
    ($cond:expr, $err:expr) => {{
        let condition_result = $cond;
        if $crate::LOCATION_LOG && !condition_result {
            $crate::println!("\n!!! Error occurred @ {}, {}", file!(), line!())
        }
        try_or(condition_result, $err)
    }};
}

#[macro_export]
macro_rules! err {
    ($err:expr) => {{
        if $crate::LOCATION_LOG {
            $crate::println!("\n!!! Error occurred @ {}, {}", file!(), line!());
        }
        err($err)
    }};
}

#[macro_export]
macro_rules! assert{
    ($cond:expr $(,)?) => {{
        let condition_result = $cond;
        if $crate::LOCATION_LOG && !condition_result {
            $crate::println!("\n!!! Error occurred @ {}, {}", file!(), line!())
        }
        ::core::assert!($cond)
    }};
    ($cond:expr, $($arg:tt)+) => {{
        let condition_result = $cond;
        if $crate::LOCATION_LOG && !condition_result {
            $crate::println!("\n!!! Error occurred @ {}, {}", file!(), line!())
        }
        ::core::assert!($cond, $($arg)+)
    }};
}

#[macro_export]
macro_rules! wrapped_err {
    ($err:expr, $wrapped:expr) => {{
        if $crate::LOCATION_LOG {
            $crate::println!("\n!!! Error occurred @ {}, {}", file!(), line!());
        }
        wrapped_err($err, $wrapped)
    }};
}

#[macro_export]
macro_rules! unwrap_or_break {
    ($result:expr) => {
        match $result {
            Ok(r) => r,
            Err(e) => {
                if $crate::LOCATION_LOG {
                    $crate::println!("\n!!! Error occurred @ {}, {}", file!(), line!());
                }
                break;
            }
        }
    };
}

pub fn try_or(cond: bool, err: Errors) -> Result<(), anyhow::Error> {
    ensure!(cond, err);
    Ok(())
}

pub fn err<T>(err: Errors) -> Result<T, anyhow::Error> {
    bail!(err)
}

pub fn wrapped_err<T: Debug>(err: Errors, src: WrappedError<T>) -> anyhow::Error {
    anyhow!("\n\tStreams Error: {}\n\t\tCause: {:?}", err, src.0)
}
