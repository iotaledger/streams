use anyhow::Result;

use crate::{
    core::prp::PRP,
    ddml::{
        commands::{
            wrap::{Wrap, Context},
            Commit,
        },
        io,
        modifiers::External,
        types::{
            NBytes,
            Bytes,
            Size,
            Uint16,
            Uint32,
            Uint64,
            Uint8,
        },
    },
};

/// Commit Spongos.
impl<F: PRP, OS> Commit for Context<F, OS> {
    fn commit(&mut self) -> Result<&mut Self> {
        self.spongos.commit();
        Ok(self)
    }
}
