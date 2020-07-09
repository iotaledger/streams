use anyhow::{
    Result,
};

use crate::types::{
    Size,
};

/// Helper trait for unwrapping (decoding/absorbing) uint8s.
pub(crate) trait Unwrap {
    fn unwrap_u8(&mut self, uint8: &mut u8) -> Result<&mut Self>;
    fn unwrapn(&mut self, trits: &mut [u8]) -> Result<&mut Self>;
}

/// Helper function for unwrapping (decoding/absorbing) size values.
pub(crate) fn unwrap_size<'a, Ctx: Unwrap>(_ctx: &'a mut Ctx, _size: &mut Size) -> Result<&'a mut Ctx> where
{
    panic!("not implemented");

    /*
    let mut d = Uint8(0);
    ctx.unwrap_u8(&mut d)?;
    ensure!(Uint8(0) <= d && d <= Uint8(13), "Invalid size of `size_t`: {}.", d);

    let mut m: i64 = 0;
    let mut r: i64 = 1;
    if 0 < d.0 {
        d.0 -= 1;
        let mut t = Uint8(0);
        ctx.unwrap_u8(&mut t)?;
        m = t.0 as i64;

        while 0 < d.0 {
            d.0 -= 1;
            ctx.unwrap_u8(&mut t)?;
            r *= 27;
            m += r * t.0 as i64;
        }

        ensure!(
            Uint8(0) < t,
            "The last most significant uint8 is `size_t` can't be 0 or negative: {}.",
            t
        );

        ensure!(SIZE_MAX >= m as usize, "`size_t` value is overflown: {}.", m);
    }

    size.0 = m as usize;
    Ok(ctx)
     */
}
