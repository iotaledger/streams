use anyhow::Result;

use crate::types::{
    size_bytes,
    Size,
    Uint8,
};

/// Helper trait for wrapping (encoding/absorbing) trint3s.
pub(crate) trait Wrap {
    fn wrap_u8(&mut self, u: u8) -> Result<&mut Self>;
    fn wrapn(&mut self, trits: &[u8]) -> Result<&mut Self>;
}

/// Helper function for wrapping (encoding/absorbing) size values.
pub(crate) fn wrap_size<'a, Ctx: Wrap>(ctx: &'a mut Ctx, size: Size) -> Result<&'a mut Ctx> where
{
    panic!("not implemented");
    //let d = size_bytes(size.0);
    //ctx.wrap_u8(Uint8(d as u8))?;

    //Ok(ctx)
}
