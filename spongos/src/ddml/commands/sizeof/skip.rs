use anyhow::Result;
use generic_array::ArrayLength;

use crate::ddml::{
    commands::{
        sizeof::Context,
        Skip,
    },
    types::{
        Bytes,
        NBytes,
        Size,
        Uint16,
        Uint32,
        Uint64,
        Uint8,
    },
};

/// Skipped values are just encoded.
/// All Uint8 values are encoded with 1 byte
impl Skip<Uint8> for Context {
    fn skip(&mut self, _u: Uint8) -> Result<&mut Self> {
        self.size += 1;
        Ok(self)
    }
}

/// Skipped values are just encoded.
/// All Uint16 values are encoded with 2 bytes
impl Skip<Uint16> for Context {
    fn skip(&mut self, _u: Uint16) -> Result<&mut Self> {
        self.size += 2;
        Ok(self)
    }
}

/// Skipped values are just encoded.
/// All Uint32 values are encoded with 4 bytes
impl Skip<Uint32> for Context {
    fn skip(&mut self, _u: Uint32) -> Result<&mut Self> {
        self.size += 4;
        Ok(self)
    }
}

/// Skipped values are just encoded.
/// All Uint64 values are encoded with 8 bytes
impl Skip<Uint64> for Context {
    fn skip(&mut self, _u: Uint64) -> Result<&mut Self> {
        self.size += 8;
        Ok(self)
    }
}

/// Size has var-size encoding.
impl Skip<Size> for Context {
    fn skip(&mut self, size: Size) -> Result<&mut Self> {
        self.size += size.num_bytes() as usize + 1;
        Ok(self)
    }
}

impl<'a> Skip<&'a Bytes> for Context {
    fn skip(&mut self, bytes: &'a Bytes) -> Result<&mut Self> {
        let bytes_size = Size::new(bytes.len());
        self.skip(bytes_size)?;
        self.size += bytes.len();
        Ok(self)
    }
}

impl<'a, T: AsRef<[u8]>> Skip<&'a NBytes<T>> for Context {
    fn skip(&mut self, nbytes: &'a NBytes<T>) -> Result<&mut Self> {
        self.size += nbytes.as_ref().len();
        Ok(self)
    }
}

// impl<F, T: AsRef<[u8]>> Skip<NBytes<T>> for Context {
//     fn skip(&mut self, nbytes: NBytes<T>) -> Result<&mut Self> {
//         self.skip(&nbytes)
//     }
// }

// TODO: REMOVE
// impl<'a, F, T: 'a + SkipFallback> Skip<&'a Fallback<T>> for Context {
//     fn skip(&mut self, val: &'a Fallback<T>) -> Result<&mut Self> {
//         (val.0).sizeof_skip(self)?;
//         Ok(self)
//     }
// }
