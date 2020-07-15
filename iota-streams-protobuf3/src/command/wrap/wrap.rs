use anyhow::Result;

use crate::types::{
    Size, size_bytes,
};

/// Helper trait for wrapping (encoding/absorbing) trint3s.
pub(crate) trait Wrap {
    fn wrap_u8(&mut self, u: u8) -> Result<&mut Self>;
    fn wrapn(&mut self, trits: &[u8]) -> Result<&mut Self>;
}

/// Helper function for wrapping (encoding/absorbing) size values.
pub(crate) fn wrap_size<'a, Ctx: Wrap>(ctx: &'a mut Ctx, size: Size) -> Result<&'a mut Ctx> where
{
    let d = size_bytes(size.0);
    ctx.wrap_u8(d as u8)?;
    let n = size.0;
    for s in (0..d).rev() {
        let r = ((n >> (s << 3)) & 0xff) as u8;
        ctx.wrap_u8(r);
    }

    Ok(ctx)
}
