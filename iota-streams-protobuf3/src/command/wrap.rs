//! Implementation of command traits for wrapping.

use failure::{ensure, Fallible};
use std::convert::AsMut;
use std::iter;
use std::mem;

use iota_streams_core::{
    prng,
    sponge::{prp::PRP, spongos::*},
    tbits::{
        trinary,
        word::{BasicTbitWord, IntTbitWord, SpongosTbitWord},
        TbitSlice, TbitSliceMut, Tbits,
    },
};
use iota_streams_core_mss::signature::mss;
use iota_streams_core_ntru::key_encapsulation::ntru;

use crate::command::*;
use crate::io;
use crate::types::*;

//#[derive(Debug)]
pub struct Context<TW, F, OS> {
    pub spongos: Spongos<TW, F>,
    pub stream: OS,
}

impl<TW, F, OS> Context<TW, F, OS>
where
    TW: SpongosTbitWord,
    F: PRP<TW> + Default,
{
    pub fn new(stream: OS) -> Self {
        Self {
            spongos: Spongos::<TW, F>::init(),
            stream: stream,
        }
    }
}

/// Helper trait for wrapping (encoding/absorbing) trint3s.
pub(crate) trait Wrap<TW> {
    fn wrap3(&mut self, trint3: Trint3) -> Fallible<&mut Self>;
    fn wrapn(&mut self, trits: TbitSlice<TW>) -> Fallible<&mut Self>;
}

/// Helper function for wrapping (encoding/absorbing) size values.
pub(crate) fn wrap_size<'a, TW, Ctx: Wrap<TW>>(
    ctx: &'a mut Ctx,
    size: Size,
) -> Fallible<&'a mut Ctx> where
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

struct AbsorbContext<TW, F, OS> {
    ctx: Context<TW, F, OS>,
}
impl<TW, F, OS> AsMut<AbsorbContext<TW, F, OS>> for Context<TW, F, OS> {
    fn as_mut<'a>(&'a mut self) -> &'a mut AbsorbContext<TW, F, OS> {
        unsafe {
            mem::transmute::<&'a mut Context<TW, F, OS>, &'a mut AbsorbContext<TW, F, OS>>(self)
        }
    }
}
impl<TW, F, OS> AsMut<Context<TW, F, OS>> for AbsorbContext<TW, F, OS> {
    fn as_mut<'a>(&'a mut self) -> &'a mut Context<TW, F, OS> {
        unsafe {
            mem::transmute::<&'a mut AbsorbContext<TW, F, OS>, &'a mut Context<TW, F, OS>>(self)
        }
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

struct AbsorbExternalContext<TW, F, OS> {
    ctx: Context<TW, F, OS>,
}
impl<TW, F, OS> AsMut<AbsorbExternalContext<TW, F, OS>> for Context<TW, F, OS> {
    fn as_mut<'a>(&'a mut self) -> &'a mut AbsorbExternalContext<TW, F, OS> {
        unsafe {
            mem::transmute::<&'a mut Context<TW, F, OS>, &'a mut AbsorbExternalContext<TW, F, OS>>(
                self,
            )
        }
    }
}
impl<TW, F, OS> AsMut<Context<TW, F, OS>> for AbsorbExternalContext<TW, F, OS> {
    fn as_mut<'a>(&'a mut self) -> &'a mut Context<TW, F, OS> {
        unsafe {
            mem::transmute::<&'a mut AbsorbExternalContext<TW, F, OS>, &'a mut Context<TW, F, OS>>(
                self,
            )
        }
    }
}

impl<TW, F, OS: io::OStream<TW>> Wrap<TW> for AbsorbExternalContext<TW, F, OS>
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

fn wrap_absorb_external_trint3<'a, TW, F, OS: io::OStream<TW>>(
    ctx: &'a mut AbsorbExternalContext<TW, F, OS>,
    trint3: Trint3,
) -> Fallible<&'a mut AbsorbExternalContext<TW, F, OS>>
where
    TW: SpongosTbitWord + trinary::TritWord,
    F: PRP<TW>,
{
    ctx.wrap3(trint3)
}
fn wrap_absorb_external_size<'a, TW, F, OS: io::OStream<TW>>(
    ctx: &'a mut AbsorbExternalContext<TW, F, OS>,
    size: Size,
) -> Fallible<&'a mut AbsorbExternalContext<TW, F, OS>>
where
    TW: SpongosTbitWord + trinary::TritWord,
    F: PRP<TW>,
{
    wrap_size(ctx, size)
}
fn wrap_absorb_external_trits<'a, TW, F, OS: io::OStream<TW>>(
    ctx: &'a mut AbsorbExternalContext<TW, F, OS>,
    trits: TbitSlice<TW>,
) -> Fallible<&'a mut AbsorbExternalContext<TW, F, OS>>
where
    TW: SpongosTbitWord + trinary::TritWord,
    F: PRP<TW>,
{
    ctx.wrapn(trits)
}

impl<'a, T: 'a, TW, F, OS: io::OStream<TW>> Absorb<&'a External<T>> for Context<TW, F, OS>
where
    TW: SpongosTbitWord + trinary::TritWord,
    F: PRP<TW>,
    Self: Absorb<External<&'a T>>,
{
    fn absorb(&mut self, external: &'a External<T>) -> Fallible<&mut Self> {
        self.absorb(External(&external.0))
    }
}

impl<'a, TW, F, OS: io::OStream<TW>> Absorb<External<&'a Trint3>> for Context<TW, F, OS>
where
    TW: SpongosTbitWord + trinary::TritWord,
    F: PRP<TW>,
{
    fn absorb(&mut self, trint3: External<&'a Trint3>) -> Fallible<&mut Self> {
        Ok(wrap_absorb_external_trint3(self.as_mut(), *trint3.0)?.as_mut())
    }
}

impl<'a, TW, F, OS: io::OStream<TW>> Absorb<External<&'a Size>> for Context<TW, F, OS>
where
    TW: SpongosTbitWord + trinary::TritWord,
    F: PRP<TW>,
{
    fn absorb(&mut self, size: External<&'a Size>) -> Fallible<&mut Self> {
        Ok(wrap_absorb_external_size(self.as_mut(), *size.0)?.as_mut())
    }
}

impl<TW, F, OS: io::OStream<TW>> Absorb<External<Size>> for Context<TW, F, OS>
where
    TW: SpongosTbitWord + trinary::TritWord,
    F: PRP<TW>,
{
    fn absorb(&mut self, size: External<Size>) -> Fallible<&mut Self> {
        self.absorb(&size)
    }
}

impl<'a, TW, F, OS: io::OStream<TW>> Absorb<External<&'a NTrytes<TW>>> for Context<TW, F, OS>
where
    TW: SpongosTbitWord + trinary::TritWord,
    F: PRP<TW>,
{
    fn absorb(&mut self, external_ntrytes: External<&'a NTrytes<TW>>) -> Fallible<&mut Self> {
        Ok(wrap_absorb_external_trits(self.as_mut(), ((external_ntrytes.0).0).slice())?.as_mut())
    }
}

impl<'a, TW, F, OS: io::OStream<TW>, P> Absorb<External<&'a mss::PublicKey<TW, P>>>
    for Context<TW, F, OS>
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

impl<'a, TW, F, OS: io::OStream<TW>> Absorb<External<&'a ntru::PublicKey<TW, F>>>
    for Context<TW, F, OS>
where
    TW: SpongosTbitWord + trinary::TritWord,
    F: PRP<TW>,
{
    fn absorb(&mut self, pk: External<&'a ntru::PublicKey<TW, F>>) -> Fallible<&mut Self> {
        ensure!((pk.0).tbits().size() == ntru::PK_SIZE);
        Ok(wrap_absorb_external_trits(self.as_mut(), (pk.0).tbits().slice())?.as_mut())
    }
}

/// This is just an external tag or hash value to-be-signed.
impl<'a, TW, F, OS> Squeeze<&'a mut External<NTrytes<TW>>> for Context<TW, F, OS>
where
    TW: SpongosTbitWord + trinary::TritWord,
    F: PRP<TW>,
{
    fn squeeze(&mut self, external_ntrytes: &'a mut External<NTrytes<TW>>) -> Fallible<&mut Self> {
        self.spongos
            .squeeze(&mut ((external_ntrytes.0).0).slice_mut());
        Ok(self)
    }
}

/// This is just an external tag or hash value to-be-signed.
impl<'a, TW, F, OS> Squeeze<External<&'a mut NTrytes<TW>>> for Context<TW, F, OS>
where
    TW: SpongosTbitWord + trinary::TritWord,
    F: PRP<TW>,
{
    fn squeeze(&mut self, external_ntrytes: External<&'a mut NTrytes<TW>>) -> Fallible<&mut Self> {
        self.spongos
            .squeeze(&mut ((external_ntrytes.0).0).slice_mut());
        Ok(self)
    }
}

/// External values are not encoded.
impl<'a, TW, F, OS: io::OStream<TW>> Squeeze<&'a Mac> for Context<TW, F, OS>
where
    TW: SpongosTbitWord + trinary::TritWord,
    F: PRP<TW>,
{
    fn squeeze(&mut self, mac: &'a Mac) -> Fallible<&mut Self> {
        self.spongos.squeeze(&mut self.stream.try_advance(mac.0)?);
        Ok(self)
    }
}

struct MaskContext<TW, F, OS> {
    ctx: Context<TW, F, OS>,
}
impl<TW, F, OS> AsMut<MaskContext<TW, F, OS>> for Context<TW, F, OS> {
    fn as_mut<'a>(&'a mut self) -> &'a mut MaskContext<TW, F, OS> {
        unsafe {
            mem::transmute::<&'a mut Context<TW, F, OS>, &'a mut MaskContext<TW, F, OS>>(self)
        }
    }
}
impl<TW, F, OS> AsMut<Context<TW, F, OS>> for MaskContext<TW, F, OS> {
    fn as_mut<'a>(&'a mut self) -> &'a mut Context<TW, F, OS> {
        unsafe {
            mem::transmute::<&'a mut MaskContext<TW, F, OS>, &'a mut Context<TW, F, OS>>(self)
        }
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

struct SkipContext<TW, F, OS> {
    ctx: Context<TW, F, OS>,
}
impl<TW, F, OS> AsMut<SkipContext<TW, F, OS>> for Context<TW, F, OS> {
    fn as_mut<'a>(&'a mut self) -> &'a mut SkipContext<TW, F, OS> {
        unsafe {
            mem::transmute::<&'a mut Context<TW, F, OS>, &'a mut SkipContext<TW, F, OS>>(self)
        }
    }
}
impl<TW, F, OS> AsMut<Context<TW, F, OS>> for SkipContext<TW, F, OS> {
    fn as_mut<'a>(&'a mut self) -> &'a mut Context<TW, F, OS> {
        unsafe {
            mem::transmute::<&'a mut SkipContext<TW, F, OS>, &'a mut Context<TW, F, OS>>(self)
        }
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
        self.skip(Size((trytes.0).size() / 3))?;
        Ok(wrap_skip_trits(self.as_mut(), (trytes.0).slice())?.as_mut())
    }
}

/// Commit Spongos.
impl<TW, F, OS> Commit for Context<TW, F, OS>
where
    TW: SpongosTbitWord + trinary::TritWord,
    F: PRP<TW>,
{
    fn commit(&mut self) -> Fallible<&mut Self> {
        self.spongos.commit();
        Ok(self)
    }
}

impl<'a, TW, F, OS: io::OStream<TW>, P> Mssig<&'a mss::PrivateKey<TW, P>, &'a External<NTrytes<TW>>>
    for Context<TW, F, OS>
where
    TW: IntTbitWord + SpongosTbitWord + trinary::TritWord,
    F: PRP<TW>,
    P: mss::Parameters<TW>,
{
    fn mssig(
        &mut self,
        sk: &'a mss::PrivateKey<TW, P>,
        hash: &'a External<NTrytes<TW>>,
    ) -> Fallible<&mut Self> {
        ensure!(
            P::HASH_SIZE == ((hash.0).0).size(),
            "Trit size of `external tryte hash[n]` to be signed with MSS must be equal {} trits.",
            P::HASH_SIZE
        );
        ensure!(sk.private_keys_left() > 0, "All WOTS private keys in MSS Merkle tree have been exhausted, nothing to sign hash with.");
        let sig_slice = self.stream.try_advance(P::signature_size(sk.height()))?;
        sk.sign(((hash.0).0).slice(), sig_slice);
        Ok(self)
    }
}

impl<'a, TW, F, OS: io::OStream<TW>, P>
    Mssig<&'a mut mss::PrivateKey<TW, P>, &'a External<NTrytes<TW>>> for Context<TW, F, OS>
where
    TW: IntTbitWord + SpongosTbitWord + trinary::TritWord,
    F: PRP<TW>,
    P: mss::Parameters<TW>,
{
    fn mssig(
        &mut self,
        sk: &'a mut mss::PrivateKey<TW, P>,
        hash: &'a External<NTrytes<TW>>,
    ) -> Fallible<&mut Self> {
        // Force convert to `&self` with a smaller life-time.
        <Self as Mssig<&'_ mss::PrivateKey<TW, P>, &'_ External<NTrytes<TW>>>>::mssig(
            self, sk, hash,
        )?;
        sk.next();
        Ok(self)
    }
}

impl<'a, TW, F, OS: io::OStream<TW>, P> Mssig<&'a mss::PrivateKey<TW, P>, MssHashSig>
    for Context<TW, F, OS>
where
    TW: IntTbitWord + SpongosTbitWord + trinary::TritWord,
    F: PRP<TW>,
    P: mss::Parameters<TW>,
{
    fn mssig(&mut self, sk: &'a mss::PrivateKey<TW, P>, _hash: MssHashSig) -> Fallible<&mut Self> {
        let mut hash = External(NTrytes(Tbits::<TW>::zero(P::HASH_SIZE)));
        self.squeeze(&mut hash)?.commit()?.mssig(sk, &hash)
    }
}

impl<'a, TW, F, OS: io::OStream<TW>, P> Mssig<&'a mut mss::PrivateKey<TW, P>, MssHashSig>
    for Context<TW, F, OS>
where
    TW: IntTbitWord + SpongosTbitWord + trinary::TritWord,
    F: PRP<TW>,
    P: mss::Parameters<TW>,
{
    fn mssig(
        &mut self,
        sk: &'a mut mss::PrivateKey<TW, P>,
        _hash: MssHashSig,
    ) -> Fallible<&mut Self> {
        let mut hash = External(NTrytes(Tbits::<TW>::zero(P::HASH_SIZE)));
        self.squeeze(&mut hash)?.commit()?.mssig(sk, &hash)
    }
}

impl<'a, TW, F, OS: io::OStream<TW>, G>
    Ntrukem<
        (
            &'a ntru::PublicKey<TW, F>,
            &'a prng::Prng<TW, G>,
            &'a Tbits<TW>,
        ),
        &'a NTrytes<TW>,
    > for Context<TW, F, OS>
where
    TW: SpongosTbitWord + trinary::TritWord,
    F: PRP<TW>,
    G: PRP<TW> + Clone + Default,
{
    fn ntrukem(
        &mut self,
        key: (
            &'a ntru::PublicKey<TW, F>,
            &'a prng::Prng<TW, G>,
            &'a Tbits<TW>,
        ),
        secret: &'a NTrytes<TW>,
    ) -> Fallible<&mut Self> {
        //TODO: ensure!(ntru::KEY_SIZE == (secret.0).size(), "Trit size of `external tryte secret[n]` to be encapsulated with NTRU must be equal {} trits.", ntru::KEY_SIZE);

        let ekey_slice = self.stream.try_advance(ntru::EKEY_SIZE)?;
        (key.0).encrypt_with_spongos(
            &mut self.spongos,
            key.1,
            (key.2).slice(),
            (secret.0).slice(),
            ekey_slice,
        );
        Ok(self)
    }
}

impl<C, TW, F, OS: io::OStream<TW>> Fork<C> for Context<TW, F, OS>
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

impl<I, C, TW, F, OS: io::OStream<TW>> Repeated<I, C> for Context<TW, F, OS>
where
    TW: SpongosTbitWord + trinary::TritWord,
    F: PRP<TW>,
    I: iter::Iterator,
    C: for<'a> FnMut(&'a mut Self, <I as iter::Iterator>::Item) -> Fallible<&'a mut Self>,
{
    fn repeated(&mut self, values_iter: I, mut value_handle: C) -> Fallible<&mut Self> {
        values_iter.fold(Ok(self), |rctx, item| -> Fallible<&mut Self> {
            match rctx {
                Ok(ctx) => value_handle(ctx, item),
                Err(e) => Err(e),
            }
        })
    }
}
impl<'a, TW, F, T: 'a + AbsorbFallback<TW, F>, OS: io::OStream<TW>> Absorb<&'a Fallback<T>>
    for Context<TW, F, OS>
{
    fn absorb(&mut self, val: &'a Fallback<T>) -> Fallible<&mut Self> {
        (val.0).wrap_absorb(self)?;
        Ok(self)
    }
}
impl<'a, TW, F, T: 'a + AbsorbExternalFallback<TW, F>, OS: io::OStream<TW>>
    Absorb<External<Fallback<&'a T>>> for Context<TW, F, OS>
{
    fn absorb(&mut self, val: External<Fallback<&'a T>>) -> Fallible<&mut Self> {
        ((val.0).0).wrap_absorb_external(self)?;
        Ok(self)
    }
}
impl<'a, TW, F, T: 'a + SkipFallback<TW, F>, OS: io::OStream<TW>> Skip<&'a Fallback<T>>
    for Context<TW, F, OS>
{
    fn skip(&mut self, val: &'a Fallback<T>) -> Fallible<&mut Self> {
        (val.0).wrap_skip(self)?;
        Ok(self)
    }
}

impl<'a, TW, F, L: SkipFallback<TW, F>, S: LinkStore<TW, F, L>, OS: io::OStream<TW>>
    Join<&'a L, &'a S> for Context<TW, F, OS>
where
    TW: SpongosTbitWord,
    F: PRP<TW>,
{
    fn join(&mut self, store: &'a S, link: &'a L) -> Fallible<&mut Self> {
        //TODO: Return and use info.
        let (mut s, _i) = store.lookup(link)?;
        link.wrap_skip(self)?;
        self.spongos.join(&mut s);
        Ok(self)
    }
}

/*
impl<'a, L, S: LinkStore<L>, TW, F, OS: io::OStream<TW>> Join<&'a L, &'a S> for Context<TW, F, OS> where
    Self: Skip<&'a L>
{
    fn join(&mut self, store: &'a S, link: &'a L) -> Fallible<&mut Self> {
        let (mut s, i) = store.lookup(link)?;
        self.skip(link)?;
        self.spongos.join(&mut s);
        Ok(self)
    }
}
 */

impl<TW, F, OS: io::OStream<TW>> Dump for Context<TW, F, OS>
where
    TW: BasicTbitWord + trinary::TritWord,
{
    fn dump<'a>(&mut self, args: std::fmt::Arguments<'a>) -> Fallible<&mut Self> {
        println!(
            "{}: ostream=[{}] spongos=[{:?}]",
            args,
            self.stream.dump(),
            self.spongos
        );
        Ok(self)
    }
}
