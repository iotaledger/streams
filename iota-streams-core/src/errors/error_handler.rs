use super::error_messages::*;
use anyhow::{ensure, anyhow};
use core::fmt::Debug;

pub struct ErrorHandler;

impl ErrorHandler {
    pub fn try_or(cond: bool, err: Errors) -> Result<(), anyhow::Error> {
        ensure!(cond, err);
        Ok(())
    }

    pub fn err<T>(err: Errors) -> Result<T, anyhow::Error> {
        Err(anyhow!(err))
    }

    pub fn panic_if_not(cond: bool) {
        assert!(cond)
    }

    pub fn wrapped_err<T: Debug>(err:Errors, src: WrappedError<T>) -> anyhow::Error {
        anyhow!("Streams Error: {}\n\tCause: {:?}", err, src.0)
    }
}


