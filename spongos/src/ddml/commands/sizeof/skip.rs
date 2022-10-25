use crate::{
    ddml::{
        commands::{sizeof::Context, Skip},
        types::{Bytes, NBytes, Size, Uint16, Uint32, Uint64, Uint8},
    },
    error::Result,
};

/// Skipped values are just encoded and not wrapped.
/// All Uint8 values are encoded with 1 byte
impl Skip<Uint8> for Context {
    fn skip(&mut self, _u: Uint8) -> Result<&mut Self> {
        self.size += 1;
        Ok(self)
    }
}

/// Skipped values are just encoded and not wrapped.
/// All Uint16 values are encoded with 2 bytes
impl Skip<Uint16> for Context {
    fn skip(&mut self, _u: Uint16) -> Result<&mut Self> {
        self.size += 2;
        Ok(self)
    }
}

/// Skipped values are just encoded and not wrapped.
/// All Uint32 values are encoded with 4 bytes
impl Skip<Uint32> for Context {
    fn skip(&mut self, _u: Uint32) -> Result<&mut Self> {
        self.size += 4;
        Ok(self)
    }
}

/// Skipped values are just encoded and not wrapped.
/// All Uint64 values are encoded with 8 bytes
impl Skip<Uint64> for Context {
    fn skip(&mut self, _u: Uint64) -> Result<&mut Self> {
        self.size += 8;
        Ok(self)
    }
}

/// Increases [`Context`] size by the number of bytes present in the provided [`Size`] wrapper.
/// `Size` has var-size encoding.
impl Skip<Size> for Context {
    fn skip(&mut self, size: Size) -> Result<&mut Self> {
        self.size += size.num_bytes() as usize + 1;
        Ok(self)
    }
}

/// Increases [`Context`] size by the number of bytes present in the provided [`Bytes`] wrapper.
/// `Bytes<bytes[n]>` has variable size thus the size `n` is encoded before the content bytes.
impl<T: AsRef<[u8]>> Skip<Bytes<T>> for Context {
    fn skip(&mut self, bytes: Bytes<T>) -> Result<&mut Self> {
        let bytes_size = Size::new(bytes.len());
        self.skip(bytes_size)?;
        self.size += bytes.len();
        Ok(self)
    }
}

/// Increases [`Context`] size by the number of bytes present in the provided [`NBytes`] wrapper.
/// `NByte<bytes[n]>` is fixed-size and is encoded with `n` bytes.
impl<T: AsRef<[u8]>> Skip<NBytes<T>> for Context {
    fn skip(&mut self, nbytes: NBytes<T>) -> Result<&mut Self> {
        self.size += nbytes.inner().as_ref().len();
        Ok(self)
    }
}
