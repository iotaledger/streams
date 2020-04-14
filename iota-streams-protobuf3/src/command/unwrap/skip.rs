use failure::Fallible;
use std::mem;

use super::{
    unwrap::*,
    Context,
};
use crate::{
    command::Skip,
    io,
    types::{
        Fallback,
        NTrytes,
        Size,
        SkipFallback,
        Trint3,
        Trytes,
    },
};
use iota_streams_core::tbits::{
    trinary,
    word::BasicTbitWord,
    TbitSliceMut,
    Tbits,
};

struct SkipContext<TW, F, IS> {
    ctx: Context<TW, F, IS>,
}
impl<TW, F, IS> AsMut<SkipContext<TW, F, IS>> for Context<TW, F, IS> {
    fn as_mut<'a>(&'a mut self) -> &'a mut SkipContext<TW, F, IS> {
        unsafe { mem::transmute::<&'a mut Context<TW, F, IS>, &'a mut SkipContext<TW, F, IS>>(self) }
    }
}
impl<TW, F, IS> AsMut<Context<TW, F, IS>> for SkipContext<TW, F, IS> {
    fn as_mut<'a>(&'a mut self) -> &'a mut Context<TW, F, IS> {
        unsafe { mem::transmute::<&'a mut SkipContext<TW, F, IS>, &'a mut Context<TW, F, IS>>(self) }
    }
}

impl<TW, F, IS: io::IStream<TW>> Unwrap<TW> for SkipContext<TW, F, IS>
where
    TW: BasicTbitWord + trinary::TritWord,
{
    fn unwrap3(&mut self, trint3: &mut Trint3) -> Fallible<&mut Self> {
        let slice = self.ctx.stream.try_advance(3)?;
        *trint3 = slice.get3();
        Ok(self)
    }
    fn unwrapn(&mut self, trits: TbitSliceMut<TW>) -> Fallible<&mut Self> {
        let slice = self.ctx.stream.try_advance(trits.size())?;
        slice.copy(&trits);
        Ok(self)
    }
}

fn unwrap_skip_trint3<'a, TW, F, IS: io::IStream<TW>>(
    ctx: &'a mut SkipContext<TW, F, IS>,
    trint3: &mut Trint3,
) -> Fallible<&'a mut SkipContext<TW, F, IS>>
where
    TW: BasicTbitWord + trinary::TritWord,
{
    ctx.unwrap3(trint3)
}
fn unwrap_skip_size<'a, TW, F, IS: io::IStream<TW>>(
    ctx: &'a mut SkipContext<TW, F, IS>,
    size: &mut Size,
) -> Fallible<&'a mut SkipContext<TW, F, IS>>
where
    TW: BasicTbitWord + trinary::TritWord,
{
    unwrap_size(ctx, size)
}
fn unwrap_skip_trits<'a, TW, F, IS: io::IStream<TW>>(
    ctx: &'a mut SkipContext<TW, F, IS>,
    trits: TbitSliceMut<TW>,
) -> Fallible<&'a mut SkipContext<TW, F, IS>>
where
    TW: BasicTbitWord + trinary::TritWord,
{
    ctx.unwrapn(trits)
}

impl<'a, TW, F, IS: io::IStream<TW>> Skip<&'a mut Trint3> for Context<TW, F, IS>
where
    TW: BasicTbitWord + trinary::TritWord,
{
    fn skip(&mut self, trint3: &'a mut Trint3) -> Fallible<&mut Self> {
        Ok(unwrap_skip_trint3(self.as_mut(), trint3)?.as_mut())
    }
}

impl<'a, TW, F, IS: io::IStream<TW>> Skip<&'a mut Size> for Context<TW, F, IS>
where
    TW: BasicTbitWord + trinary::TritWord,
{
    fn skip(&mut self, size: &'a mut Size) -> Fallible<&mut Self> {
        Ok(unwrap_skip_size(self.as_mut(), size)?.as_mut())
    }
}

impl<'a, TW, F, IS: io::IStream<TW>> Skip<&'a mut NTrytes<TW>> for Context<TW, F, IS>
where
    TW: BasicTbitWord + trinary::TritWord,
{
    fn skip(&mut self, ntrytes: &'a mut NTrytes<TW>) -> Fallible<&mut Self> {
        Ok(unwrap_skip_trits(self.as_mut(), (ntrytes.0).slice_mut())?.as_mut())
    }
}

impl<'a, TW, F, IS: io::IStream<TW>> Skip<&'a mut Trytes<TW>> for Context<TW, F, IS>
where
    TW: BasicTbitWord + trinary::TritWord,
{
    fn skip(&mut self, trytes: &'a mut Trytes<TW>) -> Fallible<&mut Self> {
        let mut size = Size(0);
        self.skip(&mut size)?;
        trytes.0 = Tbits::<TW>::zero(size.0 * 3);
        Ok(unwrap_skip_trits(self.as_mut(), (trytes.0).slice_mut())?.as_mut())
    }
}

impl<'a, TW, F, T: 'a + SkipFallback<TW, F>, IS: io::IStream<TW>> Skip<&'a mut Fallback<T>> for Context<TW, F, IS> {
    fn skip(&mut self, val: &'a mut Fallback<T>) -> Fallible<&mut Self> {
        (val.0).unwrap_skip(self)?;
        Ok(self)
    }
}
