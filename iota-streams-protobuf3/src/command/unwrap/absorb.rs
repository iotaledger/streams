use failure::{
    ensure,
    Fallible,
};
use std::mem;

use super::{
    unwrap::*,
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
        TbitSliceMut,
        Tbits,
    },
};
use iota_streams_core_mss::signature::mss;
use iota_streams_core_ntru::key_encapsulation::ntru;

struct AbsorbContext<TW, F, IS> {
    ctx: Context<TW, F, IS>,
}
impl<TW, F, IS> AsMut<AbsorbContext<TW, F, IS>> for Context<TW, F, IS> {
    fn as_mut<'a>(&'a mut self) -> &'a mut AbsorbContext<TW, F, IS> {
        unsafe { mem::transmute::<&'a mut Context<TW, F, IS>, &'a mut AbsorbContext<TW, F, IS>>(self) }
    }
}
impl<TW, F, IS> AsMut<Context<TW, F, IS>> for AbsorbContext<TW, F, IS> {
    fn as_mut<'a>(&'a mut self) -> &'a mut Context<TW, F, IS> {
        unsafe { mem::transmute::<&'a mut AbsorbContext<TW, F, IS>, &'a mut Context<TW, F, IS>>(self) }
    }
}

impl<TW, F, IS: io::IStream<TW>> Unwrap<TW> for AbsorbContext<TW, F, IS>
where
    TW: SpongosTbitWord + trinary::TritWord,
    F: PRP<TW>,
{
    fn unwrap3(&mut self, trint3: &mut Trint3) -> Fallible<&mut Self> {
        let slice = self.ctx.stream.try_advance(3)?;
        *trint3 = slice.get3();
        self.ctx.spongos.absorb(slice);
        Ok(self)
    }
    fn unwrapn(&mut self, trits: TbitSliceMut<TW>) -> Fallible<&mut Self> {
        let slice = self.ctx.stream.try_advance(trits.size())?;
        slice.copy(&trits);
        self.ctx.spongos.absorb(unsafe { trits.as_const() });
        Ok(self)
    }
}

fn unwrap_absorb_trint3<'a, TW, F, IS: io::IStream<TW>>(
    ctx: &'a mut AbsorbContext<TW, F, IS>,
    trint3: &mut Trint3,
) -> Fallible<&'a mut AbsorbContext<TW, F, IS>>
where
    TW: SpongosTbitWord + trinary::TritWord,
    F: PRP<TW>,
{
    ctx.unwrap3(trint3)
}
fn unwrap_absorb_size<'a, TW, F, IS: io::IStream<TW>>(
    ctx: &'a mut AbsorbContext<TW, F, IS>,
    size: &mut Size,
) -> Fallible<&'a mut AbsorbContext<TW, F, IS>>
where
    TW: SpongosTbitWord + trinary::TritWord,
    F: PRP<TW>,
{
    unwrap_size(ctx, size)
}
fn unwrap_absorb_trits<'a, TW, F, IS: io::IStream<TW>>(
    ctx: &'a mut AbsorbContext<TW, F, IS>,
    trits: TbitSliceMut<TW>,
) -> Fallible<&'a mut AbsorbContext<TW, F, IS>>
where
    TW: SpongosTbitWord + trinary::TritWord,
    F: PRP<TW>,
{
    ctx.unwrapn(trits)
}

impl<TW, F, IS: io::IStream<TW>> Absorb<&mut Trint3> for Context<TW, F, IS>
where
    TW: SpongosTbitWord + trinary::TritWord,
    F: PRP<TW>,
{
    fn absorb(&mut self, trint3: &mut Trint3) -> Fallible<&mut Self> {
        Ok(unwrap_absorb_trint3(self.as_mut(), trint3)?.as_mut())
    }
}

impl<TW, F, IS: io::IStream<TW>> Absorb<&mut Size> for Context<TW, F, IS>
where
    TW: SpongosTbitWord + trinary::TritWord,
    F: PRP<TW>,
{
    fn absorb(&mut self, size: &mut Size) -> Fallible<&mut Self> {
        Ok(unwrap_absorb_size(self.as_mut(), size)?.as_mut())
    }
}

impl<'a, TW, F, IS: io::IStream<TW>> Absorb<&'a mut NTrytes<TW>> for Context<TW, F, IS>
where
    TW: SpongosTbitWord + trinary::TritWord,
    F: PRP<TW>,
{
    fn absorb(&mut self, ntrytes: &'a mut NTrytes<TW>) -> Fallible<&mut Self> {
        Ok(unwrap_absorb_trits(self.as_mut(), (ntrytes.0).slice_mut())?.as_mut())
    }
}

impl<'a, TW, F, IS: io::IStream<TW>> Absorb<&'a mut Trytes<TW>> for Context<TW, F, IS>
where
    TW: SpongosTbitWord + trinary::TritWord,
    F: PRP<TW>,
{
    fn absorb(&mut self, trytes: &'a mut Trytes<TW>) -> Fallible<&mut Self> {
        let mut size = Size(0);
        self.absorb(&mut size)?;
        trytes.0 = Tbits::<TW>::zero(3 * size.0);
        Ok(unwrap_absorb_trits(self.as_mut(), (trytes.0).slice_mut())?.as_mut())
    }
}

impl<'a, TW, F, IS: io::IStream<TW>, P> Absorb<&'a mut mss::PublicKey<TW, P>> for Context<TW, F, IS>
where
    TW: SpongosTbitWord + trinary::TritWord,
    F: PRP<TW>,
    P: mss::Parameters<TW>,
{
    fn absorb(&mut self, pk: &'a mut mss::PublicKey<TW, P>) -> Fallible<&mut Self> {
        ensure!(pk.tbits().size() == P::PUBLIC_KEY_SIZE);
        Ok(unwrap_absorb_trits(self.as_mut(), pk.tbits_mut().slice_mut())?.as_mut())
    }
}

impl<'a, TW, F, IS: io::IStream<TW>> Absorb<&'a mut ntru::PublicKey<TW, F>> for Context<TW, F, IS>
where
    TW: SpongosTbitWord + trinary::TritWord,
    F: PRP<TW>,
{
    fn absorb(&mut self, pk: &'a mut ntru::PublicKey<TW, F>) -> Fallible<&mut Self> {
        ensure!(pk.tbits().size() == ntru::PUBLIC_KEY_SIZE);
        unwrap_absorb_trits(self.as_mut(), pk.tbits_mut().slice_mut())?;
        ensure!(pk.validate(), "NTRU public key is not valid.");
        Ok(self)
    }
}

impl<'a, TW, F, T: 'a + AbsorbFallback<TW, F>, IS: io::IStream<TW>> Absorb<&'a mut Fallback<T>> for Context<TW, F, IS> {
    fn absorb(&mut self, val: &'a mut Fallback<T>) -> Fallible<&mut Self> {
        (val.0).unwrap_absorb(self)?;
        Ok(self)
    }
}
