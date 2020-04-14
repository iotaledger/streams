use failure::{
    ensure,
    Fallible,
};

use crate::types::{
    Size,
    Trint3,
    SIZE_MAX,
};
use iota_streams_core::tbits::TbitSliceMut;

/// Helper trait for unwrapping (decoding/absorbing) trint3s.
pub(crate) trait Unwrap<TW> {
    fn unwrap3(&mut self, trint3: &mut Trint3) -> Fallible<&mut Self>;
    fn unwrapn(&mut self, trits: TbitSliceMut<TW>) -> Fallible<&mut Self>;
}

/// Helper function for unwrapping (decoding/absorbing) size values.
pub(crate) fn unwrap_size<'a, TW, Ctx: Unwrap<TW>>(ctx: &'a mut Ctx, size: &mut Size) -> Fallible<&'a mut Ctx> where
{
    let mut d = Trint3(0);
    ctx.unwrap3(&mut d)?;
    print!("uws d={}", d.0);
    ensure!(Trint3(0) <= d && d <= Trint3(13), "Invalid size of `size_t`: {}.", d);

    let mut m: i64 = 0;
    let mut r: i64 = 1;
    if 0 < d.0 {
        d.0 -= 1;
        let mut t = Trint3(0);
        ctx.unwrap3(&mut t)?;
        print!(" {}", t.0);
        m = t.0 as i64;

        while 0 < d.0 {
            d.0 -= 1;
            ctx.unwrap3(&mut t)?;
            print!(" {}", t.0);
            r *= 27;
            m += r * t.0 as i64;
        }

        ensure!(
            Trint3(0) < t,
            "The last most significant trint3 is `size_t` can't be 0 or negative: {}.",
            t
        );

        ensure!(SIZE_MAX >= m as usize, "`size_t` value is overflown: {}.", m);
    }

    size.0 = m as usize;
    println!(" s={}", size.0);
    Ok(ctx)
}
