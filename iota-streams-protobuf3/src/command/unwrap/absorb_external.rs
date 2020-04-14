use failure::{
    ensure,
    Fallible,
};
use std::mem;

use super::Context;
use crate::{
    command::{
        wrap::{
            wrap_size,
            Wrap,
        },
        Absorb,
    },
    io,
    types::{
        AbsorbExternalFallback,
        External,
        Fallback,
        NTrytes,
        Size,
        Trint3,
    },
};
use iota_streams_core::{
    sponge::prp::PRP,
    tbits::{
        trinary,
        word::{
            BasicTbitWord,
            SpongosTbitWord,
        },
        TbitSlice,
        TbitSliceMut,
    },
};
use iota_streams_core_mss::signature::mss;
use iota_streams_core_ntru::key_encapsulation::ntru;

struct AbsorbExternalContext<TW, F, IS> {
    ctx: Context<TW, F, IS>,
}
impl<TW, F, IS> AsMut<AbsorbExternalContext<TW, F, IS>> for Context<TW, F, IS>
where
    TW: SpongosTbitWord + trinary::TritWord,
    F: PRP<TW>,
{
    fn as_mut<'a>(&'a mut self) -> &'a mut AbsorbExternalContext<TW, F, IS> {
        unsafe { mem::transmute::<&'a mut Context<TW, F, IS>, &'a mut AbsorbExternalContext<TW, F, IS>>(self) }
    }
}
impl<TW, F, IS> AsMut<Context<TW, F, IS>> for AbsorbExternalContext<TW, F, IS> {
    fn as_mut<'a>(&'a mut self) -> &'a mut Context<TW, F, IS> {
        unsafe { mem::transmute::<&'a mut AbsorbExternalContext<TW, F, IS>, &'a mut Context<TW, F, IS>>(self) }
    }
}

impl<TW, F, IS: io::IStream<TW>> Wrap<TW> for AbsorbExternalContext<TW, F, IS>
where
    TW: SpongosTbitWord + trinary::TritWord,
    F: PRP<TW>,
{
    fn wrap3(&mut self, trint3: Trint3) -> Fallible<&mut Self> {
        let mut buf = [BasicTbitWord::ZERO_WORD; 3];
        let mut t3 = TbitSliceMut::<TW>::from_slice_mut(3, &mut buf);
        t3.put3(trint3);
        self.ctx.spongos.absorb(unsafe { t3.as_const() });
        Ok(self)
    }
    fn wrapn(&mut self, trits: TbitSlice<TW>) -> Fallible<&mut Self> {
        self.ctx.spongos.absorb(trits);
        Ok(self)
    }
}

fn wrap_absorb_external_trint3<'a, TW, F, IS: io::IStream<TW>>(
    ctx: &'a mut AbsorbExternalContext<TW, F, IS>,
    trint3: Trint3,
) -> Fallible<&'a mut AbsorbExternalContext<TW, F, IS>>
where
    TW: SpongosTbitWord + trinary::TritWord,
    F: PRP<TW>,
{
    ctx.wrap3(trint3)
}
fn wrap_absorb_external_size<'a, TW, F, IS: io::IStream<TW>>(
    ctx: &'a mut AbsorbExternalContext<TW, F, IS>,
    size: Size,
) -> Fallible<&'a mut AbsorbExternalContext<TW, F, IS>>
where
    TW: SpongosTbitWord + trinary::TritWord,
    F: PRP<TW>,
{
    wrap_size(ctx, size)
}
fn wrap_absorb_external_trits<'a, TW, F, IS: io::IStream<TW>>(
    ctx: &'a mut AbsorbExternalContext<TW, F, IS>,
    trits: TbitSlice<TW>,
) -> Fallible<&'a mut AbsorbExternalContext<TW, F, IS>>
where
    TW: SpongosTbitWord + trinary::TritWord,
    F: PRP<TW>,
{
    ctx.wrapn(trits)
}

impl<'a, T: 'a, TW, F, IS: io::IStream<TW>> Absorb<&'a External<T>> for Context<TW, F, IS>
where
    TW: SpongosTbitWord + trinary::TritWord,
    F: PRP<TW>,
    Self: Absorb<External<&'a T>>,
{
    fn absorb(&mut self, external: &'a External<T>) -> Fallible<&mut Self> {
        self.absorb(External(&external.0))
    }
}

impl<'a, TW, F, IS: io::IStream<TW>> Absorb<External<&'a Trint3>> for Context<TW, F, IS>
where
    TW: SpongosTbitWord + trinary::TritWord,
    F: PRP<TW>,
{
    fn absorb(&mut self, trint3: External<&'a Trint3>) -> Fallible<&mut Self> {
        Ok(wrap_absorb_external_trint3(self.as_mut(), *trint3.0)?.as_mut())
    }
}

impl<'a, TW, F, IS: io::IStream<TW>> Absorb<External<&'a Size>> for Context<TW, F, IS>
where
    TW: SpongosTbitWord + trinary::TritWord,
    F: PRP<TW>,
{
    fn absorb(&mut self, size: External<&'a Size>) -> Fallible<&mut Self> {
        Ok(wrap_absorb_external_size(self.as_mut(), *size.0)?.as_mut())
    }
}

impl<TW, F, IS: io::IStream<TW>> Absorb<External<Size>> for Context<TW, F, IS>
where
    TW: SpongosTbitWord + trinary::TritWord,
    F: PRP<TW>,
{
    fn absorb(&mut self, size: External<Size>) -> Fallible<&mut Self> {
        self.absorb(&size)
    }
}

impl<'a, TW, F, IS: io::IStream<TW>> Absorb<External<&'a NTrytes<TW>>> for Context<TW, F, IS>
where
    TW: SpongosTbitWord + trinary::TritWord,
    F: PRP<TW>,
{
    fn absorb(&mut self, external_ntrytes: External<&'a NTrytes<TW>>) -> Fallible<&mut Self> {
        Ok(wrap_absorb_external_trits(self.as_mut(), ((external_ntrytes.0).0).slice())?.as_mut())
    }
}

impl<'a, TW, F, IS: io::IStream<TW>, P> Absorb<External<&'a mss::PublicKey<TW, P>>> for Context<TW, F, IS>
where
    TW: SpongosTbitWord + trinary::TritWord,
    F: PRP<TW>,
    P: mss::Parameters<TW>,
{
    fn absorb(&mut self, pk: External<&'a mss::PublicKey<TW, P>>) -> Fallible<&mut Self> {
        ensure!((pk.0).tbits().size() == P::PUBLIC_KEY_SIZE);
        Ok(wrap_absorb_external_trits(self.as_mut(), (pk.0).tbits().slice())?.as_mut())
    }
}

impl<'a, TW, F, IS: io::IStream<TW>> Absorb<External<&'a ntru::PublicKey<TW, F>>> for Context<TW, F, IS>
where
    TW: SpongosTbitWord + trinary::TritWord,
    F: PRP<TW>,
{
    fn absorb(&mut self, pk: External<&'a ntru::PublicKey<TW, F>>) -> Fallible<&mut Self> {
        ensure!((pk.0).tbits().size() == ntru::PUBLIC_KEY_SIZE);
        Ok(wrap_absorb_external_trits(self.as_mut(), (pk.0).tbits().slice())?.as_mut())
    }
}

impl<'a, TW, F, T: 'a + AbsorbExternalFallback<TW, F>, IS: io::IStream<TW>> Absorb<External<Fallback<&'a T>>>
    for Context<TW, F, IS>
{
    fn absorb(&mut self, val: External<Fallback<&'a T>>) -> Fallible<&mut Self> {
        ((val.0).0).unwrap_absorb_external(self)?;
        Ok(self)
    }
}
