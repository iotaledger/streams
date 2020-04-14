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
    command::Mask,
    io,
    types::{
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

struct MaskContext<TW, F, OS> {
    ctx: Context<TW, F, OS>,
}
impl<TW, F, OS> AsMut<MaskContext<TW, F, OS>> for Context<TW, F, OS> {
    fn as_mut<'a>(&'a mut self) -> &'a mut MaskContext<TW, F, OS> {
        unsafe { mem::transmute::<&'a mut Context<TW, F, OS>, &'a mut MaskContext<TW, F, OS>>(self) }
    }
}
impl<TW, F, OS> AsMut<Context<TW, F, OS>> for MaskContext<TW, F, OS> {
    fn as_mut<'a>(&'a mut self) -> &'a mut Context<TW, F, OS> {
        unsafe { mem::transmute::<&'a mut MaskContext<TW, F, OS>, &'a mut Context<TW, F, OS>>(self) }
    }
}

impl<TW, F, OS: io::OStream<TW>> Wrap<TW> for MaskContext<TW, F, OS>
where
    TW: SpongosTbitWord + trinary::TritWord,
    F: PRP<TW>,
{
    fn wrap3(&mut self, trint3: Trint3) -> Fallible<&mut Self> {
        let mut slice = self.ctx.stream.try_advance(3)?;
        slice.put3(trint3);
        self.ctx.spongos.encrypt_mut(&mut slice);
        Ok(self)
    }
    fn wrapn(&mut self, trits: TbitSlice<TW>) -> Fallible<&mut Self> {
        let mut slice = self.ctx.stream.try_advance(trits.size())?;
        self.ctx.spongos.encrypt(trits, &mut slice);
        Ok(self)
    }
}

fn wrap_mask_trint3<'a, TW, F, OS: io::OStream<TW>>(
    ctx: &'a mut MaskContext<TW, F, OS>,
    trint3: Trint3,
) -> Fallible<&'a mut MaskContext<TW, F, OS>>
where
    TW: SpongosTbitWord + trinary::TritWord,
    F: PRP<TW>,
{
    ctx.wrap3(trint3)
}
fn wrap_mask_size<'a, TW, F, OS: io::OStream<TW>>(
    ctx: &'a mut MaskContext<TW, F, OS>,
    size: Size,
) -> Fallible<&'a mut MaskContext<TW, F, OS>>
where
    TW: SpongosTbitWord + trinary::TritWord,
    F: PRP<TW>,
{
    wrap_size(ctx, size)
}
fn wrap_mask_trits<'a, TW, F, OS: io::OStream<TW>>(
    ctx: &'a mut MaskContext<TW, F, OS>,
    trits: TbitSlice<TW>,
) -> Fallible<&'a mut MaskContext<TW, F, OS>>
where
    TW: SpongosTbitWord + trinary::TritWord,
    F: PRP<TW>,
{
    ctx.wrapn(trits)
}

impl<'a, TW, F, OS: io::OStream<TW>> Mask<&'a Trint3> for Context<TW, F, OS>
where
    TW: SpongosTbitWord + trinary::TritWord,
    F: PRP<TW>,
{
    fn mask(&mut self, trint3: &'a Trint3) -> Fallible<&mut Self> {
        Ok(wrap_mask_trint3(self.as_mut(), *trint3)?.as_mut())
    }
}

impl<'a, TW, F, OS: io::OStream<TW>> Mask<&'a Size> for Context<TW, F, OS>
where
    TW: SpongosTbitWord + trinary::TritWord,
    F: PRP<TW>,
{
    fn mask(&mut self, size: &'a Size) -> Fallible<&mut Self> {
        Ok(wrap_mask_size(self.as_mut(), *size)?.as_mut())
    }
}

impl<'a, TW, F, OS: io::OStream<TW>> Mask<&'a NTrytes<TW>> for Context<TW, F, OS>
where
    TW: SpongosTbitWord + trinary::TritWord,
    F: PRP<TW>,
{
    fn mask(&mut self, ntrytes: &'a NTrytes<TW>) -> Fallible<&mut Self> {
        Ok(wrap_mask_trits(self.as_mut(), (ntrytes.0).slice())?.as_mut())
    }
}

impl<'a, TW, F, OS: io::OStream<TW>> Mask<&'a Trytes<TW>> for Context<TW, F, OS>
where
    TW: SpongosTbitWord + trinary::TritWord,
    F: PRP<TW>,
{
    fn mask(&mut self, trytes: &'a Trytes<TW>) -> Fallible<&mut Self> {
        ensure!(
            (trytes.0).size() % 3 == 0,
            "Trit size of `trytes` must be a multiple of 3: {}.",
            (trytes.0).size()
        );
        let size = Size((trytes.0).size() / 3);
        self.mask(&size)?;
        Ok(wrap_mask_trits(self.as_mut(), (trytes.0).slice())?.as_mut())
    }
}

impl<'a, TW, F, OS: io::OStream<TW>> Mask<&'a ntru::PublicKey<TW, F>> for Context<TW, F, OS>
where
    TW: SpongosTbitWord + trinary::TritWord,
    F: PRP<TW>,
{
    fn mask(&mut self, ntru_pk: &'a ntru::PublicKey<TW, F>) -> Fallible<&mut Self> {
        Ok(wrap_mask_trits(self.as_mut(), ntru_pk.tbits().slice())?.as_mut())
    }
}

impl<'a, TW, F, OS: io::OStream<TW>, P> Mask<&'a mss::PublicKey<TW, P>> for Context<TW, F, OS>
where
    TW: SpongosTbitWord + trinary::TritWord,
    F: PRP<TW>,
    P: mss::Parameters<TW>,
{
    fn mask(&mut self, mss_pk: &'a mss::PublicKey<TW, P>) -> Fallible<&mut Self> {
        Ok(wrap_mask_trits(self.as_mut(), mss_pk.tbits().slice())?.as_mut())
    }
}
