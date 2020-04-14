use failure::{
    ensure,
    Fallible,
};
use std::mem;

use super::{
    wrap::*,
    Context,
};
use crate::{
    command::Absorb,
    io,
    types::{
        AbsorbFallback,
        Fallback,
        NTrytes,
        Size,
        Trint3,
        Trytes,
    },
};
use iota_streams_core::{
    sponge::prp::PRP,
    tbits::{
        trinary,
        word::SpongosTbitWord,
        TbitSlice,
    },
};
use iota_streams_core_mss::signature::mss;
use iota_streams_core_ntru::key_encapsulation::ntru;

struct AbsorbContext<TW, F, OS> {
    ctx: Context<TW, F, OS>,
}
impl<TW, F, OS> AsMut<AbsorbContext<TW, F, OS>> for Context<TW, F, OS> {
    fn as_mut<'a>(&'a mut self) -> &'a mut AbsorbContext<TW, F, OS> {
        unsafe { mem::transmute::<&'a mut Context<TW, F, OS>, &'a mut AbsorbContext<TW, F, OS>>(self) }
    }
}
impl<TW, F, OS> AsMut<Context<TW, F, OS>> for AbsorbContext<TW, F, OS> {
    fn as_mut<'a>(&'a mut self) -> &'a mut Context<TW, F, OS> {
        unsafe { mem::transmute::<&'a mut AbsorbContext<TW, F, OS>, &'a mut Context<TW, F, OS>>(self) }
    }
}

impl<TW, F, OS: io::OStream<TW>> Wrap<TW> for AbsorbContext<TW, F, OS>
where
    TW: SpongosTbitWord + trinary::TritWord,
    F: PRP<TW>,
{
    fn wrap3(&mut self, trint3: Trint3) -> Fallible<&mut Self> {
        let mut slice = self.ctx.stream.try_advance(3)?;
        slice.put3(trint3);
        self.ctx.spongos.absorb(unsafe { slice.as_const() });
        Ok(self)
    }
    fn wrapn(&mut self, trits: TbitSlice<TW>) -> Fallible<&mut Self> {
        self.ctx.spongos.absorb(trits);
        let slice = self.ctx.stream.try_advance(trits.size())?;
        trits.copy(&slice);
        Ok(self)
    }
}

fn wrap_absorb_trint3<'a, TW, F, OS: io::OStream<TW>>(
    ctx: &'a mut AbsorbContext<TW, F, OS>,
    trint3: Trint3,
) -> Fallible<&'a mut AbsorbContext<TW, F, OS>>
where
    TW: SpongosTbitWord + trinary::TritWord,
    F: PRP<TW>,
{
    ctx.wrap3(trint3)
}
fn wrap_absorb_size<'a, TW, F, OS: io::OStream<TW>>(
    ctx: &'a mut AbsorbContext<TW, F, OS>,
    size: Size,
) -> Fallible<&'a mut AbsorbContext<TW, F, OS>>
where
    TW: SpongosTbitWord + trinary::TritWord,
    F: PRP<TW>,
{
    wrap_size(ctx, size)
}
fn wrap_absorb_trits<'a, TW, F, OS: io::OStream<TW>>(
    ctx: &'a mut AbsorbContext<TW, F, OS>,
    trits: TbitSlice<TW>,
) -> Fallible<&'a mut AbsorbContext<TW, F, OS>>
where
    TW: SpongosTbitWord + trinary::TritWord,
    F: PRP<TW>,
{
    ctx.wrapn(trits)
}

impl<'a, TW, F, OS: io::OStream<TW>> Absorb<&'a Trint3> for Context<TW, F, OS>
where
    TW: SpongosTbitWord + trinary::TritWord,
    F: PRP<TW>,
{
    fn absorb(&mut self, trint3: &'a Trint3) -> Fallible<&mut Self> {
        Ok(wrap_absorb_trint3(self.as_mut(), *trint3)?.as_mut())
    }
}

impl<TW, F, OS: io::OStream<TW>> Absorb<Trint3> for Context<TW, F, OS>
where
    TW: SpongosTbitWord + trinary::TritWord,
    F: PRP<TW>,
{
    fn absorb(&mut self, trint3: Trint3) -> Fallible<&mut Self> {
        self.absorb(&trint3)
    }
}

impl<'a, TW, F, OS: io::OStream<TW>> Absorb<&'a Size> for Context<TW, F, OS>
where
    TW: SpongosTbitWord + trinary::TritWord,
    F: PRP<TW>,
{
    fn absorb(&mut self, size: &'a Size) -> Fallible<&mut Self> {
        Ok(wrap_absorb_size(self.as_mut(), *size)?.as_mut())
    }
}

impl<TW, F, OS: io::OStream<TW>> Absorb<Size> for Context<TW, F, OS>
where
    TW: SpongosTbitWord + trinary::TritWord,
    F: PRP<TW>,
{
    fn absorb(&mut self, size: Size) -> Fallible<&mut Self> {
        self.absorb(&size)
    }
}

impl<'a, TW, F, OS: io::OStream<TW>> Absorb<&'a NTrytes<TW>> for Context<TW, F, OS>
where
    TW: SpongosTbitWord + trinary::TritWord,
    F: PRP<TW>,
{
    fn absorb(&mut self, ntrytes: &'a NTrytes<TW>) -> Fallible<&mut Self> {
        Ok(wrap_absorb_trits(self.as_mut(), (ntrytes.0).slice())?.as_mut())
    }
}

impl<'a, TW, F, OS: io::OStream<TW>> Absorb<&'a Trytes<TW>> for Context<TW, F, OS>
where
    TW: SpongosTbitWord + trinary::TritWord,
    F: PRP<TW>,
{
    fn absorb(&mut self, trytes: &'a Trytes<TW>) -> Fallible<&mut Self> {
        self.absorb(Size((trytes.0).size() / 3))?;
        Ok(wrap_absorb_trits(self.as_mut(), (trytes.0).slice())?.as_mut())
    }
}

impl<'a, TW, F, OS: io::OStream<TW>, P> Absorb<&'a mss::PublicKey<TW, P>> for Context<TW, F, OS>
where
    TW: SpongosTbitWord + trinary::TritWord,
    F: PRP<TW>,
    P: mss::Parameters<TW>,
{
    fn absorb(&mut self, pk: &'a mss::PublicKey<TW, P>) -> Fallible<&mut Self> {
        ensure!(pk.tbits().size() == P::PUBLIC_KEY_SIZE);
        Ok(wrap_absorb_trits(self.as_mut(), pk.tbits().slice())?.as_mut())
    }
}

impl<'a, TW, F, OS: io::OStream<TW>> Absorb<&'a ntru::PublicKey<TW, F>> for Context<TW, F, OS>
where
    TW: SpongosTbitWord + trinary::TritWord,
    F: PRP<TW>,
{
    fn absorb(&mut self, pk: &'a ntru::PublicKey<TW, F>) -> Fallible<&mut Self> {
        ensure!(pk.tbits().size() == ntru::PUBLIC_KEY_SIZE);
        Ok(wrap_absorb_trits(self.as_mut(), pk.tbits().slice())?.as_mut())
    }
}

impl<'a, TW, F, T: 'a + AbsorbFallback<TW, F>, OS: io::OStream<TW>> Absorb<&'a Fallback<T>> for Context<TW, F, OS> {
    fn absorb(&mut self, val: &'a Fallback<T>) -> Fallible<&mut Self> {
        (val.0).wrap_absorb(self)?;
        Ok(self)
    }
}
