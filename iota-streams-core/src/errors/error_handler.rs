use super::error_messages::*;
use crate::{
    anyhow,
    bail,
    ensure,
};
use core::fmt::Debug;

#[macro_export]
macro_rules! try_or {
    ($cond:expr, $err:expr) => {{
        if $crate::LOCATION_LOG && !$cond {
            $crate::println!("\n!!! Error occurred @ {}, {}", file!(), line!())
        }
        try_or($cond, $err)
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
macro_rules! panic_if_not {
    ($cond:expr) => {{
        if $crate::LOCATION_LOG && !$cond {
            $crate::println!("\n!!! Error occurred @ {}, {}", file!(), line!())
        }
        panic_if_not($cond)
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

pub fn try_or(cond: bool, err: Errors) -> Result<(), anyhow::Error> {
    ensure!(cond, err);
    Ok(())
}

pub fn err<T>(err: Errors) -> Result<T, anyhow::Error> {
    bail!(err)
}

pub fn panic_if_not(cond: bool) {
    assert!(cond)
}

pub fn wrapped_err<T: Debug>(err: Errors, src: WrappedError<T>) -> anyhow::Error {
    anyhow!("\n\tStreams Error: {}\n\t\tCause: {:?}", err, src.0)
}
