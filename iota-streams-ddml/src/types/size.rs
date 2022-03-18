use core::fmt;

use iota_streams_core::Result;

/// DDML `size_t` type, unsigned.
#[derive(PartialEq, Eq, PartialOrd, Ord, Copy, Clone, Debug, Default)]
pub struct Size(pub usize);

impl Size {
    /// Number of bytes needed to encode a value of `size_t` type.
    pub fn num_bytes(self) -> u8 {
        let mut d = 0;
        let mut n = self.0;
        while n > 0 {
            n = n >> 8;
            d += 1;
        }
        d
    }

    pub fn sizeof(self) -> u8 {
        self.num_bytes() + 1
    }

    pub fn encode(&self, mut codec: impl FnMut(u8) -> Result<()>) -> Result<()> {
        let d = self.num_bytes();
        for s in (0..d).rev() {
            let r = ((self.0 >> (s << 3)) & 0xff) as u8;
            codec(r)?;
        }
        Ok(())
    }

    pub fn decode(mut codec: impl FnMut(&mut u8) -> Result<()>, mut num_bytes: u8) -> Result<Self> {
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
