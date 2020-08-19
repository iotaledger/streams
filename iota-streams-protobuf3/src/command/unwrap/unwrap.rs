use anyhow::Result;

use crate::types::Size;

/// Helper trait for unwrapping (decoding/absorbing) uint8s.
pub(crate) trait Unwrap {
    fn unwrap_u8(&mut self, uint8: &mut u8) -> Result<&mut Self>;
    fn unwrapn(&mut self, trits: &mut [u8]) -> Result<&mut Self>;
}

/// Helper function for unwrapping (decoding/absorbing) size values.
pub(crate) fn unwrap_size<'a, Ctx: Unwrap>(ctx: &'a mut Ctx, size: &mut Size) -> Result<&'a mut Ctx> where
{
    let mut d = 0_u8;
    ctx.unwrap_u8(&mut d)?;
    // ensure!(Uint8(0) <= d && d <= Uint8(13), "Invalid size of `size_t`: {}.", d);

    let mut m = 0_usize;
    while 0 < d {
        d -= 1;
        let mut t = 0_u8;
        ctx.unwrap_u8(&mut t)?;
        m = (m << 8) | (t as usize);
    }

    size.0 = m;
    Ok(ctx)
}
