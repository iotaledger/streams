//! Implementation of command traits for unwrapping.

use failure::{ensure, Fallible};
use std::convert::AsMut;
use std::mem;

use iota_streams_core::{
    sponge::{prp::PRP, spongos::*},
    tbits::{
        trinary,
        word::{BasicTbitWord, IntTbitWord, SpongosTbitWord},
        TbitSlice, TbitSliceMut, Tbits,
    },
};
use iota_streams_core_mss::signature::{mss, wots::Parameters as _};
use iota_streams_core_ntru::key_encapsulation::ntru;

use super::wrap::{wrap_size, Wrap};
use crate::command::*;
use crate::io;
use crate::types::*;

//#[derive(Debug)]
pub struct Context<TW, F, IS> {
    pub spongos: Spongos<TW, F>,
    pub stream: IS,
}

impl<TW, F, IS> Context<TW, F, IS>
where
    TW: SpongosTbitWord,
    F: PRP<TW> + Default,
{
    pub fn new(stream: IS) -> Self {
        Self {
            spongos: Spongos::<TW, F>::init(),
            stream: stream,
        }
    }
}
impl<TW, F, IS: io::IStream<TW>> Context<TW, F, IS> {
    pub fn drop(&mut self, n: Size) -> Fallible<&mut Self> {
        self.stream.try_advance(n.0)?;
        Ok(self)
        //<IS as io::IStream<TW>>::try_advance(&mut self.stream, n)
    }
}

/// Helper trait for unwrapping (decoding/absorbing) trint3s.
pub(crate) trait Unwrap<TW> {
    fn unwrap3(&mut self, trint3: &mut Trint3) -> Fallible<&mut Self>;
    fn unwrapn(&mut self, trits: TbitSliceMut<TW>) -> Fallible<&mut Self>
    where
        TW: BasicTbitWord;
}

/// Helper function for unwrapping (decoding/absorbing) size values.
pub(crate) fn unwrap_size<'a, TW, Ctx: Unwrap<TW>>(
    ctx: &'a mut Ctx,
    size: &mut Size,
) -> Fallible<&'a mut Ctx> where
{
    let mut d = Trint3(0);
    ctx.unwrap3(&mut d)?;
    ensure!(
        Trint3(0) <= d && d <= Trint3(13),
        "Invalid size of `size_t`: {}.",
        d
    );

    let mut m: i64 = 0;
    let mut r: i64 = 1;
    if 0 < d.0 {
        d.0 -= 1;
        let mut t = Trint3(0);
        ctx.unwrap3(&mut t)?;
        m = t.0 as i64;

        while 0 < d.0 {
            d.0 -= 1;
            ctx.unwrap3(&mut t)?;
            r *= 27;
            m += r * t.0 as i64;
        }

        ensure!(
            Trint3(0) < t,
            "The last most significant trint3 is `size_t` can't be 0 or negative: {}.",
            t
        );

        ensure!(
            SIZE_MAX >= m as usize,
            "`size_t` value is overflown: {}.",
            m
        );
    }

    size.0 = m as usize;
    Ok(ctx)
}

struct AbsorbContext<TW, F, IS> {
    ctx: Context<TW, F, IS>,
}
impl<TW, F, IS> AsMut<AbsorbContext<TW, F, IS>> for Context<TW, F, IS> {
    fn as_mut<'a>(&'a mut self) -> &'a mut AbsorbContext<TW, F, IS> {
        unsafe {
            mem::transmute::<&'a mut Context<TW, F, IS>, &'a mut AbsorbContext<TW, F, IS>>(self)
        }
    }
}
impl<TW, F, IS> AsMut<Context<TW, F, IS>> for AbsorbContext<TW, F, IS> {
    fn as_mut<'a>(&'a mut self) -> &'a mut Context<TW, F, IS> {
        unsafe {
            mem::transmute::<&'a mut AbsorbContext<TW, F, IS>, &'a mut Context<TW, F, IS>>(self)
        }
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

struct AbsorbExternalContext<TW, F, IS> {
    ctx: Context<TW, F, IS>,
}
impl<TW, F, IS> AsMut<AbsorbExternalContext<TW, F, IS>> for Context<TW, F, IS>
where
    TW: SpongosTbitWord + trinary::TritWord,
    F: PRP<TW>,
{
    fn as_mut<'a>(&'a mut self) -> &'a mut AbsorbExternalContext<TW, F, IS> {
        unsafe {
            mem::transmute::<&'a mut Context<TW, F, IS>, &'a mut AbsorbExternalContext<TW, F, IS>>(
                self,
            )
        }
    }
}
impl<TW, F, IS> AsMut<Context<TW, F, IS>> for AbsorbExternalContext<TW, F, IS> {
    fn as_mut<'a>(&'a mut self) -> &'a mut Context<TW, F, IS> {
        unsafe {
            mem::transmute::<&'a mut AbsorbExternalContext<TW, F, IS>, &'a mut Context<TW, F, IS>>(
                self,
            )
        }
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

impl<'a, TW, F, IS: io::IStream<TW>, P> Absorb<External<&'a mss::PublicKey<TW, P>>>
    for Context<TW, F, IS>
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

impl<'a, TW, F, IS: io::IStream<TW>> Absorb<External<&'a ntru::PublicKey<TW, F>>>
    for Context<TW, F, IS>
where
    TW: SpongosTbitWord + trinary::TritWord,
    F: PRP<TW>,
{
    fn absorb(&mut self, pk: External<&'a ntru::PublicKey<TW, F>>) -> Fallible<&mut Self> {
        ensure!((pk.0).tbits().size() == ntru::PUBLIC_KEY_SIZE);
        Ok(wrap_absorb_external_trits(self.as_mut(), (pk.0).tbits().slice())?.as_mut())
    }
}

/// This is just an external tag or hash value to-be-signed.
impl<'a, TW, F, IS> Squeeze<&'a mut External<NTrytes<TW>>> for Context<TW, F, IS>
where
    TW: SpongosTbitWord + trinary::TritWord,
    F: PRP<TW>,
{
    fn squeeze(&mut self, val: &'a mut External<NTrytes<TW>>) -> Fallible<&mut Self> {
        self.spongos.squeeze(&mut ((val.0).0).slice_mut());
        Ok(self)
    }
}

/// External values are not encoded. Squeeze and compare tag trits.
impl<'a, TW, F, IS: io::IStream<TW>> Squeeze<&'a Mac> for Context<TW, F, IS>
where
    TW: SpongosTbitWord + trinary::TritWord,
    F: PRP<TW>,
{
    fn squeeze(&mut self, val: &'a Mac) -> Fallible<&mut Self> {
        ensure!(
            self.spongos.squeeze_eq(self.stream.try_advance(val.0)?),
            "Integrity is violated, bad MAC."
        );
        Ok(self)
    }
}

struct MaskContext<TW, F, IS> {
    ctx: Context<TW, F, IS>,
}
impl<TW, F, IS> AsMut<MaskContext<TW, F, IS>> for Context<TW, F, IS> {
    fn as_mut<'a>(&'a mut self) -> &'a mut MaskContext<TW, F, IS> {
        unsafe {
            mem::transmute::<&'a mut Context<TW, F, IS>, &'a mut MaskContext<TW, F, IS>>(self)
        }
    }
}
impl<TW, F, IS> AsMut<Context<TW, F, IS>> for MaskContext<TW, F, IS> {
    fn as_mut<'a>(&'a mut self) -> &'a mut Context<TW, F, IS> {
        unsafe {
            mem::transmute::<&'a mut MaskContext<TW, F, IS>, &'a mut Context<TW, F, IS>>(self)
        }
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

struct SkipContext<TW, F, IS> {
    ctx: Context<TW, F, IS>,
}
impl<TW, F, IS> AsMut<SkipContext<TW, F, IS>> for Context<TW, F, IS> {
    fn as_mut<'a>(&'a mut self) -> &'a mut SkipContext<TW, F, IS> {
        unsafe {
            mem::transmute::<&'a mut Context<TW, F, IS>, &'a mut SkipContext<TW, F, IS>>(self)
        }
    }
}
impl<TW, F, IS> AsMut<Context<TW, F, IS>> for SkipContext<TW, F, IS> {
    fn as_mut<'a>(&'a mut self) -> &'a mut Context<TW, F, IS> {
        unsafe {
            mem::transmute::<&'a mut SkipContext<TW, F, IS>, &'a mut Context<TW, F, IS>>(self)
        }
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

/// Commit Spongos.
impl<TW, F, IS> Commit for Context<TW, F, IS>
where
    TW: SpongosTbitWord + trinary::TritWord,
    F: PRP<TW>,
{
    fn commit(&mut self) -> Fallible<&mut Self> {
        self.spongos.commit();
        Ok(self)
    }
}

/// Recover public key.
impl<'a, TW, F, IS: io::IStream<TW>, P>
    Mssig<&'a mut mss::PublicKey<TW, P>, &'a External<NTrytes<TW>>> for Context<TW, F, IS>
where
    TW: IntTbitWord + SpongosTbitWord + trinary::TritWord,
    F: PRP<TW>,
    P: mss::Parameters<TW>,
{
    fn mssig(
        &mut self,
        apk: &'a mut mss::PublicKey<TW, P>,
        hash: &'a External<NTrytes<TW>>,
    ) -> Fallible<&mut Self> {
        ensure!(
            P::HASH_SIZE == ((hash.0).0).size(),
            "Trit size of `external tryte hash[n]` to be signed with MSS must be equal {} trits.",
            P::HASH_SIZE
        );
        ensure!(
            P::PUBLIC_KEY_SIZE == apk.tbits().size(),
            "Trit size of MSS public key must be equal {} trits.",
            P::PUBLIC_KEY_SIZE
        );

        let skn_slice = self.stream.try_advance(P::SKN_SIZE)?;
        let d_skn = mss::parse_skn::<TW, P>(skn_slice);
        ensure!(
            d_skn.is_some(),
            "Failed to parse MSS signature skn: {:?}.",
            skn_slice
        );
        let (d, skn) = d_skn.unwrap();
        let n = P::apath_size(d);
        let wotsig_apath_slice = self
            .stream
            .try_advance(P::WotsParameters::SIGNATURE_SIZE + n)?;
        let (wotsig, apath) = wotsig_apath_slice.split_at(P::WotsParameters::SIGNATURE_SIZE);
        mss::recover_apk::<TW, P>(
            d,
            skn,
            ((hash.0).0).slice(),
            wotsig,
            apath,
            apk.tbits_mut().slice_mut(),
        );
        Ok(self)
    }
}

impl<'a, TW, F, IS: io::IStream<TW>, P> Mssig<&'a mss::PublicKey<TW, P>, &'a External<NTrytes<TW>>>
    for Context<TW, F, IS>
where
    TW: IntTbitWord + SpongosTbitWord + trinary::TritWord,
    F: PRP<TW>,
    P: mss::Parameters<TW>,
{
    fn mssig(
        &mut self,
        pk: &'a mss::PublicKey<TW, P>,
        hash: &'a External<NTrytes<TW>>,
    ) -> Fallible<&mut Self> {
        let mut apk = mss::PublicKey::<TW, P>::default();
        self.mssig(&mut apk, hash)?;
        ensure!(apk == *pk, "Authenticity is violated, bad signature.");
        Ok(self)
    }
}

impl<'a, TW, F, IS: io::IStream<TW>, P> Mssig<&'a mut mss::PublicKey<TW, P>, MssHashSig>
    for Context<TW, F, IS>
where
    TW: IntTbitWord + SpongosTbitWord + trinary::TritWord,
    F: PRP<TW>,
    P: mss::Parameters<TW>,
{
    fn mssig(
        &mut self,
        apk: &'a mut mss::PublicKey<TW, P>,
        _hash: MssHashSig,
    ) -> Fallible<&mut Self> {
        let mut hash = External(NTrytes::<TW>(Tbits::<TW>::zero(P::HASH_SIZE)));
        self.squeeze(&mut hash)?.commit()?.mssig(apk, &hash)
    }
}

impl<'a, TW, F, IS: io::IStream<TW>, P> Mssig<&'a mss::PublicKey<TW, P>, MssHashSig>
    for Context<TW, F, IS>
where
    TW: IntTbitWord + SpongosTbitWord + trinary::TritWord,
    F: PRP<TW>,
    P: mss::Parameters<TW>,
{
    fn mssig(&mut self, pk: &'a mss::PublicKey<TW, P>, _hash: MssHashSig) -> Fallible<&mut Self> {
        let mut hash = External(NTrytes::<TW>(Tbits::<TW>::zero(P::HASH_SIZE)));
        self.squeeze(&mut hash)?.commit()?.mssig(pk, &hash)
    }
}

impl<'a, TW, F, IS: io::IStream<TW>> Ntrukem<&'a ntru::PrivateKey<TW, F>, &'a mut NTrytes<TW>>
    for Context<TW, F, IS>
where
    TW: SpongosTbitWord + trinary::TritWord,
    F: PRP<TW>,
{
    fn ntrukem(
        &mut self,
        sk: &'a ntru::PrivateKey<TW, F>,
        secret: &'a mut NTrytes<TW>,
    ) -> Fallible<&mut Self> {
        //TODO: ensure!(ntru::KEY_SIZE == (secret.0).size(), "Trit size of `external tryte secret[n]` to be encapsulated with NTRU must be equal {} trits.", ntru::KEY_SIZE);

        let ekey_slice = self.stream.try_advance(ntru::EKEY_SIZE)?;
        ensure!(
            sk.decrypt_with_spongos(&mut self.spongos, ekey_slice, (secret.0).slice_mut()),
            "Failed to decapsulate secret."
        );
        Ok(self)
    }
}

impl<C, TW, F, IS: io::IStream<TW>> Fork<C> for Context<TW, F, IS>
where
    TW: SpongosTbitWord + trinary::TritWord,
    F: PRP<TW> + Clone,
    C: for<'a> FnMut(&'a mut Self) -> Fallible<&'a mut Self>,
{
    fn fork(&mut self, mut cont: C) -> Fallible<&mut Self> {
        let saved_fork = self.spongos.fork();
        cont(self)?;
        self.spongos = saved_fork;
        Ok(self)
    }
}

impl<C, TW, F, IS: io::IStream<TW>> Repeated<Size, C> for Context<TW, F, IS>
where
    TW: SpongosTbitWord + trinary::TritWord,
    F: PRP<TW>,
    C: for<'a> FnMut(&'a mut Self) -> Fallible<&'a mut Self>,
{
    fn repeated(&mut self, n: Size, mut value_handle: C) -> Fallible<&mut Self> {
        for _ in 0..(n.0) {
            value_handle(self)?;
        }
        Ok(self)
    }
}

impl<'a, TW, F, T: 'a + AbsorbFallback<TW, F>, IS: io::IStream<TW>> Absorb<&'a mut Fallback<T>>
    for Context<TW, F, IS>
{
    fn absorb(&mut self, val: &'a mut Fallback<T>) -> Fallible<&mut Self> {
        (val.0).unwrap_absorb(self)?;
        Ok(self)
    }
}
impl<'a, TW, F, T: 'a + AbsorbExternalFallback<TW, F>, IS: io::IStream<TW>>
    Absorb<External<Fallback<&'a T>>> for Context<TW, F, IS>
{
    fn absorb(&mut self, val: External<Fallback<&'a T>>) -> Fallible<&mut Self> {
        ((val.0).0).unwrap_absorb_external(self)?;
        Ok(self)
    }
}
impl<'a, TW, F, T: 'a + SkipFallback<TW, F>, IS: io::IStream<TW>> Skip<&'a mut Fallback<T>>
    for Context<TW, F, IS>
{
    fn skip(&mut self, val: &'a mut Fallback<T>) -> Fallible<&mut Self> {
        (val.0).unwrap_skip(self)?;
        Ok(self)
    }
}

impl<'a, TW, F, L: SkipFallback<TW, F>, S: LinkStore<TW, F, L>, IS: io::IStream<TW>>
    Join<&'a mut L, &S> for Context<TW, F, IS>
where
    TW: SpongosTbitWord,
    F: PRP<TW>,
{
    fn join(&mut self, store: &S, link: &'a mut L) -> Fallible<&mut Self> {
        //TODO: Move `skip` out of `join` and `skip` links explicitly.
        // That way it's easier to handle the case when the link is not found
        // and calling function can try to fetch and parse message for the link.
        //TODO: Implement a strategy (depth of recursion or max number of retries)
        // for such cases.
        link.unwrap_skip(self)?;
        //TODO: Return and use info.
        let (mut s, _i) = store.lookup(link)?;
        self.spongos.join(&mut s);
        Ok(self)
    }
}

/*
impl<'a, L, S: LinkStore<L>, IS: io::IStream<TW>> Join<&'a mut L, &S> for Context<TW, F, IS> where
    Self: Skip<&'a mut L>,
{
    fn join(&mut self, store: &S, link: &'a mut L) -> Fallible<&mut Self> {
        self.skip(link)?;
        let (mut s, i) = store.lookup(link)?;
        self.spongos.join(&mut s);
        Ok(self)
    }
}
 */

impl<TW, F, IS: io::IStream<TW>> Dump for Context<TW, F, IS>
where
    TW: SpongosTbitWord + trinary::TritWord,
{
    fn dump<'a>(&mut self, args: std::fmt::Arguments<'a>) -> Fallible<&mut Self> {
        println!(
            "{}: istream=[{}] spongos=[{:?}]",
            args,
            self.stream.dump(),
            self.spongos
        );
        Ok(self)
    }
}
