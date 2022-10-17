//! Implementation of command traits for wrapping.

use crate::{
    core::{
        prp::{keccak::KeccakF1600, PRP},
        spongos::Spongos,
    },
    ddml::types::{Size, Uint16, Uint32, Uint64, Uint8},
    error::Result,
};

/// Wrapped state of message. Used to encode `DDML` variables to
pub struct Context<OS, F = KeccakF1600> {
    /// The [`Spongos`] object representing the current state of the wrap [`Context`]
    spongos: Spongos<F>,
    /// The writing stream bytes will be wrapped into
    stream: OS,
}

/// Context for wrapping bytes.
impl<OS, F> Context<OS, F> {
    /// Creates a new [`Context`].
    pub fn new(stream: OS) -> Self
    where
        F: Default,
    {
        Self {
            spongos: Spongos::<F>::init(),
            stream,
        }
    }

    /// Creates a new [`Context`] from a provided write stream and [`Spongos`] state. Used for
    /// forking `DDML` operations. This allows for a copy of an existing [`Context`] to be used.
    pub(crate) fn new_with_spongos(stream: OS, spongos: Spongos<F>) -> Self {
        Self { spongos, stream }
    }

    /// The write stream of the current [`Context`].
    pub fn stream(&self) -> &OS {
        &self.stream
    }

    /// A mutable reference to the write stream of the current [`Context`].
    pub(crate) fn stream_mut(&mut self) -> &mut OS {
        &mut self.stream
    }

    /// Commit the [`Spongos`] outer state, ensuring all wrapped bytes are consolidated
    pub fn finalize(mut self) -> Spongos<F>
    where
        F: PRP,
    {
        self.spongos.commit();
        self.spongos
    }
}

/// Helper trait for wrapping (encoding/absorbing) uint8s.
/// Base trait for encoding binary data into an [OStream](`crate::ddml::io::OStream`)
///
/// The different commands that write data to the output stream implement
/// this trait to perform their particular cryptographic processing while
/// writing data.
trait Wrap {
    /// Write variable amount `n` bytes into the context
    fn wrapn<T>(&mut self, v: T) -> Result<&mut Self>
    where
        T: AsRef<[u8]>;
    /// Encode a single byte into the context
    fn wrap_u8(&mut self, u: Uint8) -> Result<&mut Self> {
        self.wrapn(&u.to_bytes())
    }
    /// Encode two bytes into the context
    fn wrap_u16(&mut self, u: Uint16) -> Result<&mut Self> {
        self.wrapn(&u.to_bytes())
    }
    /// Encode four bytes into the context
    fn wrap_u32(&mut self, u: Uint32) -> Result<&mut Self> {
        self.wrapn(&u.to_bytes())
    }
    /// Encode eight bytes into the context
    fn wrap_u64(&mut self, u: Uint64) -> Result<&mut Self> {
        self.wrapn(&u.to_bytes())
    }
    /// Encode the number of bytes a [`Size`] needs to encode, then encode the [`Size`] value one
    /// byte at a time
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
