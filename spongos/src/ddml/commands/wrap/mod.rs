//! Implementation of command traits for wrapping.
use anyhow::Result;

use crate::{
    core::{
        prp::PRP,
        spongos::Spongos,
    },
    ddml::types::{
        Size,
        Uint16,
        Uint32,
        Uint64,
        Uint8,
    },
};

pub struct Context<F, OS> {
    spongos: Spongos<F>,
    stream: OS,
}

impl<F, OS> Context<F, OS> {
    pub fn new(stream: OS) -> Self
    where
        F: Default,
    {
        Self {
            spongos: Spongos::<F>::init(),
            stream,
        }
    }

    pub(crate) fn new_with_spongos(stream: OS, spongos: Spongos<F>) -> Self {
        Self { spongos, stream }
    }

    pub fn stream(&self) -> &OS {
        &self.stream
    }

    pub(crate) fn stream_mut(&mut self) -> &mut OS {
        &mut self.stream
    }

    pub fn finalize(mut self) -> Spongos<F>
    where
        F: PRP,
    {
        self.spongos.commit();
        self.spongos
    }
}

trait Wrap {
    fn wrapn<T>(&mut self, v: T) -> Result<&mut Self>
    where
        T: AsRef<[u8]>;
    fn wrap_u8(&mut self, u: Uint8) -> Result<&mut Self> {
        self.wrapn(&u.to_bytes())
    }
    fn wrap_u16(&mut self, u: Uint16) -> Result<&mut Self> {
        self.wrapn(&u.to_bytes())
    }
    fn wrap_u32(&mut self, u: Uint32) -> Result<&mut Self> {
        self.wrapn(&u.to_bytes())
    }
    fn wrap_u64(&mut self, u: Uint64) -> Result<&mut Self> {
        self.wrapn(&u.to_bytes())
    }
    fn wrap_size(&mut self, size: Size) -> Result<&mut Self> where {
        self.wrap_u8(Uint8::new(size.num_bytes()))?;
        size.encode(|byte| {
            self.wrap_u8(Uint8::new(byte))?;
            Ok(())
        })?;
        Ok(self)
    }
}

mod absorb;
mod absorb_external;
mod commit;
#[cfg(feature = "std")]
mod dump;
mod fork;
mod guard;
mod join;
mod mask;
mod repeated;
mod skip;
mod squeeze;

mod ed25519;
mod x25519;
