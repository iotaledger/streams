use anyhow::{
    ensure,
    Result,
};

use crate::{
    core::prp::PRP,
    ddml::{
        commands::{
            wrap::{
                Context,
                Wrap,
            },
            Guard,
        },
        io,
        modifiers::External,
        types::{
            Bytes,
            NBytes,
            Size,
            Uint16,
            Uint32,
            Uint64,
            Uint8,
        },
    },
};

impl<F, IS> Guard for Context<F, IS> {
    fn guard<E>(&mut self, cond: bool, err: E) -> Result<&mut Self>
    where
        E: Into<anyhow::Error>,
    {
        ensure!(cond, err);
        Ok(self)
    }
}
