use anyhow::Result;

use crate::{
    core::{
        prp::PRP,
        spongos::Spongos,
    },
    ddml::{
        commands::{
            wrap::{
                Context,
                Wrap,
            },
            Join,
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

impl<F: PRP, OS> Join<F> for Context<F, OS> {
    fn join(&mut self, joinee: &mut Spongos<F>) -> Result<&mut Self> {
        // TODO: Return and use info.
        self.spongos.join(joinee);
        Ok(self)
    }
}
