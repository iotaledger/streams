use iota_streams_core::Result;

use crate::types::{
    Size,
    Uint16,
    Uint32,
    Uint64,
    Uint8,
};

/// Helper trait for unwrapping (decoding/absorbing) uint8s.
/// Base trait for decoding binary data from an [`IStream`]
///
/// The different commands that read data from the input stream implement
/// this trait to perform their particular cryptographic processing while
/// reading data.
pub(crate) trait Unwrap {
    fn unwrapn(&mut self, v: &mut [u8]) -> Result<&mut Self>;

    fn unwrap_u8(&mut self, u: &mut Uint8) -> Result<&mut Self> {
        let mut v = [0_u8; 1];
        self.unwrapn(&mut v)?;
        u.0 = v[0];
        *u = Uint8::from_bytes(v);
        Ok(self)
    }
    fn unwrap_u16(&mut self, u: &mut Uint16) -> Result<&mut Self> {
        let mut v = [0_u8; 2];
        self.unwrapn(&mut v)?;
        *u = Uint16::from_bytes(v);
        Ok(self)
    }
    fn unwrap_u32(&mut self, u: &mut Uint32) -> Result<&mut Self> {
        let mut v = [0_u8; 4];
        self.unwrapn(&mut v)?;
        *u = Uint32::from_bytes(v);
        Ok(self)
    }
    fn unwrap_u64(&mut self, u: &mut Uint64) -> Result<&mut Self> {
        let mut v = [0_u8; 8];
        self.unwrapn(&mut v)?;
        *u = Uint64::from_bytes(v);
        Ok(self)
    }
    fn unwrap_size(&mut self, size: &mut Size) -> Result<&mut Self> where {
        let mut num_bytes = Uint8(0_u8);
        self.unwrap_u8(&mut num_bytes)?;
        *size = Size::decode(
            |byte| {
                let mut typed_byte = Uint8(*byte);
                self.unwrap_u8(&mut typed_byte)?;
                *byte = typed_byte.0;
                Ok(())
            },
            num_bytes.0,
        )?;
        Ok(self)
    }
}
