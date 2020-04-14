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
        word::{
            BasicTbitWord,
            SpongosTbitWord,
        },
        TbitSlice,
        TbitSliceMut,
        Tbits,
    },
};
use iota_streams_core_mss::signature::mss;
use iota_streams_core_ntru::key_encapsulation::ntru;

struct MaskContext<TW, F, IS> {
    ctx: Context<TW, F, IS>,
}
impl<TW, F, IS> AsMut<MaskContext<TW, F, IS>> for Context<TW, F, IS> {
    fn as_mut<'a>(&'a mut self) -> &'a mut MaskContext<TW, F, IS> {
        unsafe { mem::transmute::<&'a mut Context<TW, F, IS>, &'a mut MaskContext<TW, F, IS>>(self) }
    }
}
impl<TW, F, IS> AsMut<Context<TW, F, IS>> for MaskContext<TW, F, IS> {
    fn as_mut<'a>(&'a mut self) -> &'a mut Context<TW, F, IS> {
        unsafe { mem::transmute::<&'a mut MaskContext<TW, F, IS>, &'a mut Context<TW, F, IS>>(self) }
    }
}

impl<TW, F, IS: io::IStream<TW>> Unwrap<TW> for MaskContext<TW, F, IS>
where
    TW: SpongosTbitWord + trinary::TritWord,
    F: PRP<TW>,
{
    fn unwrap3(&mut self, trint3: &mut Trint3) -> Fallible<&mut Self> {
        // 3 words should be enough to encode trint3 for any TE.
        let mut buf = [BasicTbitWord::ZERO_WORD; 3];
        let slice = self.ctx.stream.try_advance(3)?;
        {
            let mut t3 = TbitSliceMut::<TW>::from_slice_mut(3, &mut buf);
            self.ctx.spongos.decrypt(slice, &mut t3);
        }
        {
            let t3 = TbitSlice::<TW>::from_slice(3, &buf);
            *trint3 = t3.get3();
        }
        Ok(self)
    }
    fn unwrapn(&mut self, mut trits: TbitSliceMut<TW>) -> Fallible<&mut Self> {
        let slice = self.ctx.stream.try_advance(trits.size())?;
        slice.copy(&trits);
        self.ctx.spongos.decrypt_mut(&mut trits);
        Ok(self)
    }
}

fn unwrap_mask_trint3<'a, TW, F, IS: io::IStream<TW>>(
    ctx: &'a mut MaskContext<TW, F, IS>,
    trint3: &mut Trint3,
) -> Fallible<&'a mut MaskContext<TW, F, IS>>
where
    TW: SpongosTbitWord + trinary::TritWord,
    F: PRP<TW>,
{
    ctx.unwrap3(trint3)
}
fn unwrap_mask_size<'a, TW, F, IS: io::IStream<TW>>(
    ctx: &'a mut MaskContext<TW, F, IS>,
    size: &mut Size,
) -> Fallible<&'a mut MaskContext<TW, F, IS>>
where
    TW: SpongosTbitWord + trinary::TritWord,
    F: PRP<TW>,
{
    unwrap_size(ctx, size)
}
fn unwrap_mask_trits<'a, TW, F, IS: io::IStream<TW>>(
    ctx: &'a mut MaskContext<TW, F, IS>,
    trits: TbitSliceMut<TW>,
) -> Fallible<&'a mut MaskContext<TW, F, IS>>
where
    TW: SpongosTbitWord + trinary::TritWord,
    F: PRP<TW>,
{
    ctx.unwrapn(trits)
}

impl<'a, TW, F, IS: io::IStream<TW>> Mask<&'a mut Trint3> for Context<TW, F, IS>
where
    TW: SpongosTbitWord + trinary::TritWord,
    F: PRP<TW>,
{
    fn mask(&mut self, trint3: &'a mut Trint3) -> Fallible<&mut Self> {
        Ok(unwrap_mask_trint3(self.as_mut(), trint3)?.as_mut())
    }
}

impl<'a, TW, F, IS: io::IStream<TW>> Mask<&'a mut Size> for Context<TW, F, IS>
where
    TW: SpongosTbitWord + trinary::TritWord,
    F: PRP<TW>,
{
    fn mask(&mut self, size: &'a mut Size) -> Fallible<&mut Self> {
        Ok(unwrap_mask_size(self.as_mut(), size)?.as_mut())
    }
}

impl<'a, TW, F, IS: io::IStream<TW>> Mask<&'a mut NTrytes<TW>> for Context<TW, F, IS>
where
    TW: SpongosTbitWord + trinary::TritWord,
    F: PRP<TW>,
{
    fn mask(&mut self, ntrytes: &'a mut NTrytes<TW>) -> Fallible<&mut Self> {
        Ok(unwrap_mask_trits(self.as_mut(), (ntrytes.0).slice_mut())?.as_mut())
    }
}

impl<'a, TW, F, IS: io::IStream<TW>> Mask<&'a mut Trytes<TW>> for Context<TW, F, IS>
where
    TW: SpongosTbitWord + trinary::TritWord,
    F: PRP<TW>,
{
    fn mask(&mut self, trytes: &'a mut Trytes<TW>) -> Fallible<&mut Self> {
        let mut size = Size(0);
        self.mask(&mut size)?;
        trytes.0 = Tbits::<TW>::zero(size.0 * 3);
        Ok(unwrap_mask_trits(self.as_mut(), (trytes.0).slice_mut())?.as_mut())
    }
}

impl<'a, TW, F, IS: io::IStream<TW>> Mask<&'a mut ntru::PublicKey<TW, F>> for Context<TW, F, IS>
where
    TW: SpongosTbitWord + trinary::TritWord,
    F: PRP<TW>,
{
    fn mask(&mut self, ntru_pk: &'a mut ntru::PublicKey<TW, F>) -> Fallible<&mut Self> {
        ensure!(ntru_pk.tbits().size() == ntru::PUBLIC_KEY_SIZE);
        unwrap_mask_trits(self.as_mut(), ntru_pk.tbits_mut().slice_mut())?;
        ensure!(ntru_pk.validate(), "Unmasked NTRU public key is not valid.");
        Ok(self)
    }
}

impl<'a, TW, F, IS: io::IStream<TW>, P> Mask<&'a mut mss::PublicKey<TW, P>> for Context<TW, F, IS>
where
    TW: SpongosTbitWord + trinary::TritWord,
    F: PRP<TW>,
    P: mss::Parameters<TW>,
{
    fn mask(&mut self, mss_pk: &'a mut mss::PublicKey<TW, P>) -> Fallible<&mut Self> {
        ensure!(mss_pk.tbits().size() == P::PUBLIC_KEY_SIZE);
        Ok(unwrap_mask_trits(self.as_mut(), mss_pk.tbits_mut().slice_mut())?.as_mut())
    }
}
