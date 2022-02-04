use iota_streams_core::Result;

use crate::types::{
    Size,
    Uint16,
    Uint32,
    Uint64,
    Uint8,
};

/// Helper trait for wrapping (encoding/absorbing) trint3s.
pub(crate) trait Wrap {
    fn wrapn(&mut self, v: &[u8]) -> Result<&mut Self>;
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
        self.wrap_u8(Uint8(size.num_bytes()))?;
        size.encode(|byte| {
            self.wrap_u8(Uint8(byte))?;
            Ok(())
        })?;
        Ok(self)
    }
}
