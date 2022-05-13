//! Implementation of command traits for unwrapping.
use core::fmt;

use anyhow::Result;

use crate::{
    core::{
        prp::{
            keccak::KeccakF1600,
            PRP,
        },
        spongos::Spongos,
    },
    ddml::{
        io,
        types::{
            Size,
            Uint16,
            Uint32,
            Uint64,
            Uint8,
        },
    },
};

#[derive(Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct Context<IS, F = KeccakF1600> {
    spongos: Spongos<F>,
    stream: IS,
    cursor: usize,
}

impl<IS, F> Context<IS, F> {
    pub fn new(stream: IS) -> Self
    where
        F: Default,
    {
        Self {
            spongos: Spongos::<F>::init(),
            stream,
            cursor: 0,
        }
    }

    pub fn new_with_spongos(stream: IS, spongos: Spongos<F>) -> Self {
        Self {
            spongos,
            stream,
            cursor: 0,
        }
    }

    pub fn stream(&self) -> &IS {
        &self.stream
    }

    pub(crate) fn stream_mut(&mut self) -> &mut IS {
        &mut self.stream
    }

    pub fn drop(&mut self, bytes: usize) -> Result<&mut Self>
    where
        IS: io::IStream,
    {
        self.stream.try_advance(bytes)?;
        self.cursor += bytes;
        Ok(self)
    }

    pub fn finalize(mut self) -> (Spongos<F>, usize)
    where
        F: PRP,
    {
        self.spongos.commit();
        (self.spongos, self.cursor)
    }
}

impl<IS, F> fmt::Debug for Context<IS, F> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{{header: {:?}, ctx: {:?}}}", "self.header", "self.ctx")
    }
}

/// Helper trait for unwrapping (decoding/absorbing) uint8s.
/// Base trait for decoding binary data from an [`IStream`]
///
/// The different commands that read data from the input stream implement
/// this trait to perform their particular cryptographic processing while
/// reading data.
trait Unwrap {
    fn unwrapn<T>(&mut self, v: T) -> Result<&mut Self>
    where
        T: AsMut<[u8]>;

    fn unwrap_u8(&mut self, u: &mut Uint8) -> Result<&mut Self> {
        let mut v = [0u8; 1];
        self.unwrapn(&mut v)?;
        *u = Uint8::from_bytes(v);
        Ok(self)
    }
    fn unwrap_u16(&mut self, u: &mut Uint16) -> Result<&mut Self> {
        let mut v = [0u8; 2];
        self.unwrapn(&mut v)?;
        *u = Uint16::from_bytes(v);
        Ok(self)
    }
    fn unwrap_u32(&mut self, u: &mut Uint32) -> Result<&mut Self> {
        let mut v = [0u8; 4];
        self.unwrapn(&mut v)?;
        *u = Uint32::from_bytes(v);
        Ok(self)
    }
    fn unwrap_u64(&mut self, u: &mut Uint64) -> Result<&mut Self> {
        let mut v = [0u8; 8];
        self.unwrapn(&mut v)?;
        *u = Uint64::from_bytes(v);
        Ok(self)
    }
    fn unwrap_size(&mut self, size: &mut Size) -> Result<&mut Self> {
        let mut num_bytes = Uint8::new(0u8);
        self.unwrap_u8(&mut num_bytes)?;
        *size = Size::decode(
            |byte| {
                let mut typed_byte = Uint8::new(*byte);
                self.unwrap_u8(&mut typed_byte)?;
                *byte = typed_byte.inner();
                Ok(())
            },
            num_bytes.inner(),
        )?;
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
