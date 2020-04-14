use failure::Fallible;
use std::mem;

use super::{
    wrap::*,
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
    TbitSlice,
};

struct SkipContext<TW, F, OS> {
    ctx: Context<TW, F, OS>,
}
impl<TW, F, OS> AsMut<SkipContext<TW, F, OS>> for Context<TW, F, OS> {
    fn as_mut<'a>(&'a mut self) -> &'a mut SkipContext<TW, F, OS> {
        unsafe { mem::transmute::<&'a mut Context<TW, F, OS>, &'a mut SkipContext<TW, F, OS>>(self) }
    }
}
impl<TW, F, OS> AsMut<Context<TW, F, OS>> for SkipContext<TW, F, OS> {
    fn as_mut<'a>(&'a mut self) -> &'a mut Context<TW, F, OS> {
        unsafe { mem::transmute::<&'a mut SkipContext<TW, F, OS>, &'a mut Context<TW, F, OS>>(self) }
    }
}

impl<TW, F, OS: io::OStream<TW>> Wrap<TW> for SkipContext<TW, F, OS>
where
    TW: BasicTbitWord + trinary::TritWord,
{
    fn wrap3(&mut self, trint3: Trint3) -> Fallible<&mut Self> {
        let mut slice = self.ctx.stream.try_advance(3)?;
        slice.put3(trint3);
        Ok(self)
    }
    fn wrapn(&mut self, trits: TbitSlice<TW>) -> Fallible<&mut Self> {
        let slice = self.ctx.stream.try_advance(trits.size())?;
        trits.copy(&slice);
        Ok(self)
    }
}

fn wrap_skip_trint3<'a, TW, F, OS: io::OStream<TW>>(
    ctx: &'a mut SkipContext<TW, F, OS>,
    trint3: Trint3,
) -> Fallible<&'a mut SkipContext<TW, F, OS>>
where
    TW: BasicTbitWord + trinary::TritWord,
{
    ctx.wrap3(trint3)
}
fn wrap_skip_size<'a, TW, F, OS: io::OStream<TW>>(
    ctx: &'a mut SkipContext<TW, F, OS>,
    size: Size,
) -> Fallible<&'a mut SkipContext<TW, F, OS>>
where
    TW: BasicTbitWord + trinary::TritWord,
{
    wrap_size(ctx, size)
}
fn wrap_skip_trits<'a, TW, F, OS: io::OStream<TW>>(
    ctx: &'a mut SkipContext<TW, F, OS>,
    trits: TbitSlice<TW>,
) -> Fallible<&'a mut SkipContext<TW, F, OS>>
where
    TW: BasicTbitWord + trinary::TritWord,
{
    ctx.wrapn(trits)
}

impl<'a, TW, F, OS: io::OStream<TW>> Skip<&'a Trint3> for Context<TW, F, OS>
where
    TW: BasicTbitWord + trinary::TritWord,
{
    fn skip(&mut self, trint3: &'a Trint3) -> Fallible<&mut Self> {
        Ok(wrap_skip_trint3(self.as_mut(), *trint3)?.as_mut())
    }
}

impl<TW, F, OS: io::OStream<TW>> Skip<Trint3> for Context<TW, F, OS>
where
    TW: BasicTbitWord + trinary::TritWord,
{
    fn skip(&mut self, val: Trint3) -> Fallible<&mut Self> {
        self.skip(&val)
    }
}

impl<'a, TW, F, OS: io::OStream<TW>> Skip<&'a Size> for Context<TW, F, OS>
where
    TW: BasicTbitWord + trinary::TritWord,
{
    fn skip(&mut self, size: &'a Size) -> Fallible<&mut Self> {
        Ok(wrap_skip_size(self.as_mut(), *size)?.as_mut())
    }
}

impl<TW, F, OS: io::OStream<TW>> Skip<Size> for Context<TW, F, OS>
where
    TW: BasicTbitWord + trinary::TritWord,
{
    fn skip(&mut self, val: Size) -> Fallible<&mut Self> {
        self.skip(&val)
    }
}

impl<'a, TW, F, OS: io::OStream<TW>> Skip<&'a NTrytes<TW>> for Context<TW, F, OS>
where
    TW: BasicTbitWord + trinary::TritWord,
{
    fn skip(&mut self, ntrytes: &'a NTrytes<TW>) -> Fallible<&mut Self> {
        Ok(wrap_skip_trits(self.as_mut(), (ntrytes.0).slice())?.as_mut())
    }
}

impl<'a, TW, F, OS: io::OStream<TW>> Skip<&'a Trytes<TW>> for Context<TW, F, OS>
where
    TW: BasicTbitWord + trinary::TritWord,
{
    fn skip(&mut self, trytes: &'a Trytes<TW>) -> Fallible<&mut Self> {
        wrap_skip_size(self.as_mut(), Size((trytes.0).size() / 3))?;
        Ok(wrap_skip_trits(self.as_mut(), (trytes.0).slice())?.as_mut())
    }
}

impl<'a, TW, F, T: 'a + SkipFallback<TW, F>, OS: io::OStream<TW>> Skip<&'a Fallback<T>> for Context<TW, F, OS> {
    fn skip(&mut self, val: &'a Fallback<T>) -> Fallible<&mut Self> {
        (val.0).wrap_skip(self)?;
        Ok(self)
    }
}
