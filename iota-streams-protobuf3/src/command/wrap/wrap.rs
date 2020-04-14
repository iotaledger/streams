use failure::Fallible;

use crate::types::{
    size_trytes,
    Size,
    Trint3,
};
use iota_streams_core::tbits::{
    trinary,
    TbitSlice,
};

/// Helper trait for wrapping (encoding/absorbing) trint3s.
pub(crate) trait Wrap<TW> {
    fn wrap3(&mut self, trint3: Trint3) -> Fallible<&mut Self>;
    fn wrapn(&mut self, trits: TbitSlice<TW>) -> Fallible<&mut Self>;
}

/// Helper function for wrapping (encoding/absorbing) size values.
pub(crate) fn wrap_size<'a, TW, Ctx: Wrap<TW>>(ctx: &'a mut Ctx, size: Size) -> Fallible<&'a mut Ctx> where
{
    let d = size_trytes(size.0);
    ctx.wrap3(Trint3(d as i8))?;

    let mut n = size.0;
    for _ in 0..d {
        let (r, q) = trinary::mods3_usize(n);
        ctx.wrap3(r)?;
        n = q;
    }
    Ok(ctx)
}
