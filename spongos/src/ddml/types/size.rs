use core::fmt;

use crate::error::Result;

/// Integer size wrapper for `DDML` operations
#[derive(PartialEq, Eq, PartialOrd, Ord, Copy, Clone, Debug, Default)]
pub struct Size(usize);

impl Size {
    /// Create a [`Size`] wrapper for `DDML` operations
    ///
    /// # Arguments
    /// * `n`: the `usize` to be wrapped.
    pub fn new(n: usize) -> Self {
        Self(n)
    }

    /// Returns the inner `usize`.
    pub fn inner(&self) -> usize {
        self.0
    }

    /// Returns the number of bytes needed to encode a value of [`Size`] type.
    pub(crate) fn num_bytes(self) -> u8 {
        let mut d = 0;
        let mut n = self.0;
        while n > 0 {
            n >>= 8;
            d += 1;
        }
        d
    }

    /// Encodes inner `usize` into a byte array.
    ///
    /// # Arguments
    /// * `codec`: a function for encoding bytes to a [`Spongos`] stream
    pub(crate) fn encode(&self, mut codec: impl FnMut(u8) -> Result<()>) -> Result<()> {
        let d = self.num_bytes();
        for s in (0..d).rev() {
            let r = ((self.0 >> (s << 3)) & 0xff) as u8;
            codec(r)?;
        }
        Ok(())
    }

    /// Decodes inner `usize` from a byte array.
    ///
    /// # Arguments
    /// * `codec`: a function for decoding bytes from a [`Spongos`] stream
    pub(crate) fn decode(mut codec: impl FnMut(&mut u8) -> Result<()>, mut num_bytes: u8) -> Result<Self> {
        let mut result = 0usize;
        while 0 < num_bytes {
            num_bytes -= 1;
            let mut t = 0;
            codec(&mut t)?;
            result = (result << 8) | t as usize;
        }
        Ok(Size(result))
    }
}

impl fmt::Display for Size {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Size({})", self.0)
    }
}
