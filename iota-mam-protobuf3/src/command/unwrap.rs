use failure::{ensure};
use std::convert::AsMut;
use std::mem;

use iota_mam_core::trits::{word::BasicTritWord, DefaultTritWord, Trits, TritSlice, TritSliceMut};
use iota_mam_core::spongos::*;
use iota_mam_core::signature::{mss, wots};
use iota_mam_core::key_encapsulation::ntru;

use crate::io;
use crate::Result;
use crate::command::*;
use crate::types::*;
use super::wrap::{Wrap, wrap_size};

#[derive(Debug)]
pub struct Context<IS> {
    pub spongos: Spongos,
    pub stream: IS,
}

impl<IS> Context<IS> {
    pub fn new(stream: IS) -> Self {
        Self {
            spongos: Spongos::init(),
            stream: stream,
        }
    }
}
impl<IS: io::IStream> Context<IS> {
    pub fn drop(&mut self, n: Size) -> Result<&mut Self> {
        self.stream.try_advance(n.0)?;
        Ok(self)
        //<IS as io::IStream>::try_advance(&mut self.stream, n)
    }
}

/// Helper trait for unwrapping (decoding/absorbing) trint3s.
pub(crate) trait Unwrap {
    fn unwrap3(&mut self, trint3: &mut Trint3) -> Result<&mut Self>;
    fn unwrapn(&mut self, trits: TritSliceMut) -> Result<&mut Self>;
}

/// Helper function for unwrapping (decoding/absorbing) size values.
pub(crate) fn unwrap_size<'a, Ctx: Unwrap>(ctx: &'a mut Ctx, size: &mut Size) -> Result<&'a mut Ctx> where
{
    let mut d = Trint3(0);
    ctx.unwrap3(&mut d)?;
    ensure!(Trint3(0) <= d && d <= Trint3(13), "Invalid size of `size_t`: {}.", d);

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

        ensure!(Trint3(0) < t, "The last most significant trint3 is `size_t` can't be 0 or negative: {}.", t);

        ensure!(SIZE_MAX >= m as usize, "`size_t` value is overflown: {}.", m);
    }

    size.0 = m as usize;
    Ok(ctx)
}

struct AbsorbContext<IS> {
    ctx: Context<IS>,
}
impl<IS> AsMut<AbsorbContext<IS>> for Context<IS> {
    fn as_mut<'a>(&'a mut self) -> &'a mut AbsorbContext<IS> {
        unsafe { mem::transmute::<&'a mut Context<IS>, &'a mut AbsorbContext<IS>>(self) }
    }
}
impl<IS> AsMut<Context<IS>> for AbsorbContext<IS> {
    fn as_mut<'a>(&'a mut self) -> &'a mut Context<IS> {
        unsafe { mem::transmute::<&'a mut AbsorbContext<IS>, &'a mut Context<IS>>(self) }
    }
}

impl<IS: io::IStream> Unwrap for AbsorbContext<IS> {
    fn unwrap3(&mut self, trint3: &mut Trint3) -> Result<&mut Self> {
        let slice = self.ctx.stream.try_advance(3)?;
        *trint3 = slice.get3();
        self.ctx.spongos.absorb(slice);
        Ok(self)
    }
    fn unwrapn(&mut self, trits: TritSliceMut) -> Result<&mut Self> {
        let slice = self.ctx.stream.try_advance(trits.size())?;
        slice.copy(trits);
        self.ctx.spongos.absorb(trits.as_const());
        Ok(self)
    }
}

fn unwrap_absorb_trint3<'a, IS: io::IStream>(ctx: &'a mut AbsorbContext<IS>, trint3: &mut Trint3) -> Result<&'a mut AbsorbContext<IS>> where
{
    ctx.unwrap3(trint3)
}
fn unwrap_absorb_size<'a, IS: io::IStream>(ctx: &'a mut AbsorbContext<IS>, size: &mut Size) -> Result<&'a mut AbsorbContext<IS>> where
{
    unwrap_size(ctx, size)
}
fn unwrap_absorb_trits<'a, IS: io::IStream>(ctx: &'a mut AbsorbContext<IS>, trits: TritSliceMut) -> Result<&'a mut AbsorbContext<IS>> where
{
    ctx.unwrapn(trits)
}

impl<IS: io::IStream> Absorb<&mut Trint3> for Context<IS> {
    fn absorb(&mut self, trint3: &mut Trint3) -> Result<&mut Self> {
        Ok(unwrap_absorb_trint3(self.as_mut(), trint3)?.as_mut())
    }
}

impl<IS: io::IStream> Absorb<&mut Size> for Context<IS> {
    fn absorb(&mut self, size: &mut Size) -> Result<&mut Self> {
        Ok(unwrap_absorb_size(self.as_mut(), size)?.as_mut())
    }
}

impl<'a, IS: io::IStream> Absorb<&'a mut NTrytes> for Context<IS> {
    fn absorb(&mut self, ntrytes: &'a mut NTrytes) -> Result<&mut Self> {
        Ok(unwrap_absorb_trits(self.as_mut(), (ntrytes.0).slice_mut())?.as_mut())
    }
}

impl<'a, IS: io::IStream> Absorb<&'a mut Trytes> for Context<IS> {
    fn absorb(&mut self, trytes: &'a mut Trytes) -> Result<&mut Self> {
        let mut size = Size(0);
        self.absorb(&mut size)?;
        trytes.0 = Trits::zero(3 * size.0);
        Ok(unwrap_absorb_trits(self.as_mut(), (trytes.0).slice_mut())?.as_mut())
    }
}

impl<'a, IS: io::IStream> Absorb<&'a mut mss::PublicKey> for Context<IS> {
    fn absorb(&mut self, pk: &'a mut mss::PublicKey) -> Result<&mut Self> {
        ensure!(pk.pk.size() == mss::PK_SIZE);
        Ok(unwrap_absorb_trits(self.as_mut(), pk.pk.slice_mut())?.as_mut())
    }
}

impl<'a, IS: io::IStream> Absorb<&'a mut ntru::PublicKey> for Context<IS> {
    fn absorb(&mut self, pk: &'a mut ntru::PublicKey) -> Result<&mut Self> {
        ensure!(pk.pk.size() == ntru::PK_SIZE);
        unwrap_absorb_trits(self.as_mut(), pk.pk.slice_mut())?;
        ensure!(pk.validate(), "NTRU public key is not valid.");
        Ok(self)
    }
}

struct AbsorbExternalContext<IS> {
    ctx: Context<IS>,
}
impl<IS> AsMut<AbsorbExternalContext<IS>> for Context<IS> {
    fn as_mut<'a>(&'a mut self) -> &'a mut AbsorbExternalContext<IS> {
        unsafe { mem::transmute::<&'a mut Context<IS>, &'a mut AbsorbExternalContext<IS>>(self) }
    }
}
impl<IS> AsMut<Context<IS>> for AbsorbExternalContext<IS> {
    fn as_mut<'a>(&'a mut self) -> &'a mut Context<IS> {
        unsafe { mem::transmute::<&'a mut AbsorbExternalContext<IS>, &'a mut Context<IS>>(self) }
    }
}

impl<IS: io::IStream> Wrap for AbsorbExternalContext<IS> {
    fn wrap3(&mut self, trint3: Trint3) -> Result<&mut Self> {
        let mut buf = [<DefaultTritWord as BasicTritWord>::zero(); 3];
        let t3 = TritSliceMut::from_slice_mut(3, &mut buf);
        t3.put3(trint3);
        self.ctx.spongos.absorb(t3.as_const());
        Ok(self)
    }
    fn wrapn(&mut self, trits: TritSlice) -> Result<&mut Self> {
        self.ctx.spongos.absorb(trits);
        Ok(self)
    }
}

fn wrap_absorb_external_trint3<'a, IS: io::IStream>(ctx: &'a mut AbsorbExternalContext<IS>, trint3: Trint3) -> Result<&'a mut AbsorbExternalContext<IS>> where
{
    ctx.wrap3(trint3)
}
fn wrap_absorb_external_size<'a, IS: io::IStream>(ctx: &'a mut AbsorbExternalContext<IS>, size: Size) -> Result<&'a mut AbsorbExternalContext<IS>> where
{
    wrap_size(ctx, size)
}
fn wrap_absorb_external_trits<'a, IS: io::IStream>(ctx: &'a mut AbsorbExternalContext<IS>, trits: TritSlice) -> Result<&'a mut AbsorbExternalContext<IS>> where
{
    ctx.wrapn(trits)
}

impl<'a, T: 'a, IS: io::IStream> Absorb<&'a External<T>> for Context<IS> where
    Self: Absorb<External<&'a T>>
{
    fn absorb(&mut self, external: &'a External<T>) -> Result<&mut Self> {
        self.absorb(External(&external.0))
    }
}

impl<'a, IS: io::IStream> Absorb<External<&'a Size>> for Context<IS> {
    fn absorb(&mut self, size: External<&'a Size>) -> Result<&mut Self> {
        Ok(wrap_absorb_external_size(self.as_mut(), *size.0)?.as_mut())
    }
}

impl<IS: io::IStream> Absorb<External<Size>> for Context<IS> {
    fn absorb(&mut self, size: External<Size>) -> Result<&mut Self> {
        self.absorb(&size)
    }
}

impl<'a, IS: io::IStream> Absorb<External<&'a NTrytes>> for Context<IS> {
    fn absorb(&mut self, external_ntrytes: External<&'a NTrytes>) -> Result<&mut Self> {
        Ok(wrap_absorb_external_trits(self.as_mut(), ((external_ntrytes.0).0).slice())?.as_mut())
    }
}

impl<'a, IS: io::IStream> Absorb<External<&'a mss::PublicKey>> for Context<IS> {
    fn absorb(&mut self, pk: External<&'a mss::PublicKey>) -> Result<&mut Self> {
        ensure!((pk.0).pk.size() == mss::PK_SIZE);
        Ok(wrap_absorb_external_trits(self.as_mut(), (pk.0).pk.slice())?.as_mut())
    }
}

impl<'a, IS: io::IStream> Absorb<External<&'a ntru::PublicKey>> for Context<IS> {
    fn absorb(&mut self, pk: External<&'a ntru::PublicKey>) -> Result<&mut Self> {
        ensure!((pk.0).pk.size() == ntru::PK_SIZE);
        Ok(wrap_absorb_external_trits(self.as_mut(), (pk.0).pk.slice())?.as_mut())
    }
}



/// This is just an external tag or hash value to-be-signed.
impl<'a, IS> Squeeze<&'a mut External<NTrytes>> for Context<IS> {
    fn squeeze(&mut self, val: &'a mut External<NTrytes>) -> Result<&mut Self> {
        self.spongos.squeeze(((val.0).0).slice_mut());
        Ok(self)
    }
}

/// External values are not encoded. Squeeze and compare tag trits.
impl<'a, IS: io::IStream> Squeeze<&'a Mac> for Context<IS> {
    fn squeeze(&mut self, val: &'a Mac) -> Result<&mut Self> {
        ensure!(self.spongos.squeeze_eq(self.stream.try_advance(val.0)?), "Integrity is violated, bad MAC.");
        Ok(self)
    }
}

struct MaskContext<IS> {
    ctx: Context<IS>,
}
impl<IS> AsMut<MaskContext<IS>> for Context<IS> {
    fn as_mut<'a>(&'a mut self) -> &'a mut MaskContext<IS> {
        unsafe { mem::transmute::<&'a mut Context<IS>, &'a mut MaskContext<IS>>(self) }
    }
}
impl<IS> AsMut<Context<IS>> for MaskContext<IS> {
    fn as_mut<'a>(&'a mut self) -> &'a mut Context<IS> {
        unsafe { mem::transmute::<&'a mut MaskContext<IS>, &'a mut Context<IS>>(self) }
    }
}

impl<IS: io::IStream> Unwrap for MaskContext<IS> {
    fn unwrap3(&mut self, trint3: &mut Trint3) -> Result<&mut Self> {
        // 3 words should be enough to encode trint3 for any TE.
        let mut buf = [<DefaultTritWord as BasicTritWord>::zero(); 3];
        let slice = self.ctx.stream.try_advance(3)?;
        let t3 = TritSliceMut::from_slice_mut(3, &mut buf);
        self.ctx.spongos.decr(slice, t3);
        *trint3 = t3.as_const().get3();
        Ok(self)
    }
    fn unwrapn(&mut self, trits: TritSliceMut) -> Result<&mut Self> {
        let slice = self.ctx.stream.try_advance(trits.size())?;
        slice.copy(trits);
        self.ctx.spongos.decr_mut(trits);
        Ok(self)
    }
}

fn unwrap_mask_trint3<'a, IS: io::IStream>(ctx: &'a mut MaskContext<IS>, trint3: &mut Trint3) -> Result<&'a mut MaskContext<IS>> where
{
    ctx.unwrap3(trint3)
}
fn unwrap_mask_size<'a, IS: io::IStream>(ctx: &'a mut MaskContext<IS>, size: &mut Size) -> Result<&'a mut MaskContext<IS>> where
{
    unwrap_size(ctx, size)
}
fn unwrap_mask_trits<'a, IS: io::IStream>(ctx: &'a mut MaskContext<IS>, trits: TritSliceMut) -> Result<&'a mut MaskContext<IS>> where
{
    ctx.unwrapn(trits)
}

impl<'a, IS: io::IStream> Mask<&'a mut Trint3> for Context<IS> {
    fn mask(&mut self, trint3: &'a mut Trint3) -> Result<&mut Self> {
        Ok(unwrap_mask_trint3(self.as_mut(), trint3)?.as_mut())
    }
}

impl<'a, IS: io::IStream> Mask<&'a mut Size> for Context<IS> {
    fn mask(&mut self, size: &'a mut Size) -> Result<&mut Self> {
        Ok(unwrap_mask_size(self.as_mut(), size)?.as_mut())
    }
}

impl<'a, IS: io::IStream> Mask<&'a mut NTrytes> for Context<IS> {
    fn mask(&mut self, ntrytes: &'a mut NTrytes) -> Result<&mut Self> {
        Ok(unwrap_mask_trits(self.as_mut(), (ntrytes.0).slice_mut())?.as_mut())
    }
}

impl<'a, IS: io::IStream> Mask<&'a mut Trytes> for Context<IS> {
    fn mask(&mut self, trytes: &'a mut Trytes) -> Result<&mut Self> {
        let mut size = Size(0);
        self.mask(&mut size)?;
        trytes.0 = Trits::zero(size.0 * 3);
        Ok(unwrap_mask_trits(self.as_mut(), (trytes.0).slice_mut())?.as_mut())
    }
}

struct SkipContext<IS> {
    ctx: Context<IS>,
}
impl<IS> AsMut<SkipContext<IS>> for Context<IS> {
    fn as_mut<'a>(&'a mut self) -> &'a mut SkipContext<IS> {
        unsafe { mem::transmute::<&'a mut Context<IS>, &'a mut SkipContext<IS>>(self) }
    }
}
impl<IS> AsMut<Context<IS>> for SkipContext<IS> {
    fn as_mut<'a>(&'a mut self) -> &'a mut Context<IS> {
        unsafe { mem::transmute::<&'a mut SkipContext<IS>, &'a mut Context<IS>>(self) }
    }
}

impl<IS: io::IStream> Unwrap for SkipContext<IS> {
    fn unwrap3(&mut self, trint3: &mut Trint3) -> Result<&mut Self> {
        let slice = self.ctx.stream.try_advance(3)?;
        *trint3 = slice.get3();
        Ok(self)
    }
    fn unwrapn(&mut self, trits: TritSliceMut) -> Result<&mut Self> {
        let slice = self.ctx.stream.try_advance(trits.size())?;
        slice.copy(trits);
        Ok(self)
    }
}

fn unwrap_skip_trint3<'a, IS: io::IStream>(ctx: &'a mut SkipContext<IS>, trint3: &mut Trint3) -> Result<&'a mut SkipContext<IS>> where
{
    ctx.unwrap3(trint3)
}
fn unwrap_skip_size<'a, IS: io::IStream>(ctx: &'a mut SkipContext<IS>, size: &mut Size) -> Result<&'a mut SkipContext<IS>> where
{
    unwrap_size(ctx, size)
}
fn unwrap_skip_trits<'a, IS: io::IStream>(ctx: &'a mut SkipContext<IS>, trits: TritSliceMut) -> Result<&'a mut SkipContext<IS>> where
{
    ctx.unwrapn(trits)
}

impl<'a, IS: io::IStream> Skip<&'a mut Trint3> for Context<IS> {
    fn skip(&mut self, trint3: &'a mut Trint3) -> Result<&mut Self> {
        Ok(unwrap_skip_trint3(self.as_mut(), trint3)?.as_mut())
    }
}

impl<'a, IS: io::IStream> Skip<&'a mut Size> for Context<IS> {
    fn skip(&mut self, size: &'a mut Size) -> Result<&mut Self> {
        Ok(unwrap_skip_size(self.as_mut(), size)?.as_mut())
    }
}

impl<'a, IS: io::IStream> Skip<&'a mut NTrytes> for Context<IS> {
    fn skip(&mut self, ntrytes: &'a mut NTrytes) -> Result<&mut Self> {
        Ok(unwrap_skip_trits(self.as_mut(), (ntrytes.0).slice_mut())?.as_mut())
    }
}

impl<'a, IS: io::IStream> Skip<&'a mut Trytes> for Context<IS> {
    fn skip(&mut self, trytes: &'a mut Trytes) -> Result<&mut Self> {
        let mut size = Size(0);
        self.skip(&mut size)?;
        trytes.0 = Trits::zero(size.0 * 3);
        Ok(unwrap_skip_trits(self.as_mut(), (trytes.0).slice_mut())?.as_mut())
    }
}

/// Commit Spongos.
impl<IS> Commit for Context<IS> {
    fn commit(&mut self) -> Result<&mut Self> {
        self.spongos.commit();
        Ok(self)
    }
}

/// Recover public key.
impl<'a, IS: io::IStream> Mssig<&'a mut mss::PublicKey, &'a External<NTrytes>> for Context<IS> {
    fn mssig(&mut self, apk: &'a mut mss::PublicKey, hash: &'a External<NTrytes>) -> Result<&mut Self> {
        ensure!(mss::HASH_SIZE == ((hash.0).0).size(), "Trit size of `external tryte hash[n]` to be signed with MSS must be equal {} trits.", mss::HASH_SIZE);
        ensure!(mss::PK_SIZE == apk.pk.size(), "Trit size of MSS public key must be equal {} trits.", mss::PK_SIZE);

        let skn_slice = self.stream.try_advance(mss::SKN_SIZE)?;
        let d_skn = mss::parse_skn(skn_slice);
        ensure!(d_skn.is_some(), "Failed to parse MSS signature skn.");
        let (d, skn) = d_skn.unwrap();
        let n = mss::apath_size(d.0 as usize);
        let wotsig_apath_slice = self.stream.try_advance(wots::SIG_SIZE + n)?;
        let (wotsig, apath) = wotsig_apath_slice.split_at(wots::SIG_SIZE);
        mss::recover_apk(d, skn, ((hash.0).0).slice(), wotsig, apath, apk.pk.slice_mut());
        Ok(self)
    }
}

impl<'a, IS: io::IStream> Mssig<&'a mss::PublicKey, &'a External<NTrytes>> for Context<IS> {
    fn mssig(&mut self, pk: &'a mss::PublicKey, hash: &'a External<NTrytes>) -> Result<&mut Self> {
        let mut apk = mss::PublicKey::default();
        self.mssig(&mut apk, hash)?;
        println!("apk={:?} pk={:?}", apk, pk);
        ensure!(apk == *pk, "Authenticity is violated, bad signature.");
        Ok(self)
    }
}

impl<'a, IS: io::IStream> Mssig<&'a mut mss::PublicKey, MssHashSig> for Context<IS> {
    fn mssig(&mut self, apk: &'a mut mss::PublicKey, _hash: MssHashSig) -> Result<&mut Self> {
        let mut hash = External(NTrytes(Trits::zero(mss::HASH_SIZE)));
        self
            .squeeze(&mut hash)?
            .commit()?
            .mssig(apk, &hash)
    }
}

impl<'a, IS: io::IStream> Mssig<&'a mss::PublicKey, MssHashSig> for Context<IS> {
    fn mssig(&mut self, pk: &'a mss::PublicKey, _hash: MssHashSig) -> Result<&mut Self> {
        let mut hash = External(NTrytes(Trits::zero(mss::HASH_SIZE)));
        self
            .squeeze(&mut hash)?
            .commit()?
            .mssig(pk, &hash)
    }
}

impl<'a, IS: io::IStream> Ntrukem<&'a ntru::PrivateKey, &'a mut NTrytes> for Context<IS> {
    fn ntrukem(&mut self, sk: &'a ntru::PrivateKey, secret: &'a mut NTrytes) -> Result<&mut Self> {
        ensure!(ntru::KEY_SIZE == (secret.0).size(), "Trit size of `external tryte secret[n]` to be encapsulated with NTRU must be equal {} trits.", ntru::KEY_SIZE);

        let ekey_slice = self.stream.try_advance(ntru::EKEY_SIZE)?;
        ensure!(sk.decr_with_s(&mut self.spongos, ekey_slice, (secret.0).slice_mut()), "Failed to decapsulate secret.");
        Ok(self)
    }
}


impl<F, IS: io::IStream> Fork<F> for Context<IS> where
    F: for<'a> FnMut(&'a mut Self) -> Result<&'a mut Self>
{
    fn fork(&mut self, mut cont: F) -> Result<&mut Self> {
        let mut saved_fork = self.spongos.fork();
        cont(self)?;
        self.spongos = saved_fork;
        Ok(self)
    }
}

impl<F, IS: io::IStream> Repeated<Size, F> for Context<IS> where
    F: for<'a> FnMut(&'a mut Self) -> Result<&'a mut Self>,
{
    fn repeated(&mut self, mut n: Size, mut value_handle: F) -> Result<&mut Self> {
        for _ in 0..(n.0) {
            value_handle(self)?;
        }
        Ok(self)
    }
}



impl<'a, T: 'a + AbsorbFallback, IS: io::IStream> Absorb<&'a mut T> for Context<IS> {
    fn absorb(&mut self, val: &'a mut T) -> Result<&mut Self> {
        val.unwrap_absorb(self)?;
        Ok(self)
    }
}
impl<'a, T: 'a + AbsorbExternalFallback, IS: io::IStream> Absorb<External<&'a T>> for Context<IS> {
    fn absorb(&mut self, val: External<&'a T>) -> Result<&mut Self> {
        (val.0).unwrap_absorb_external(self)?;
        Ok(self)
    }
}
impl<'a, T: 'a + SkipFallback, IS: io::IStream> Skip<&'a mut T> for Context<IS> {
    fn skip(&mut self, val: &'a mut T) -> Result<&mut Self> {
        val.unwrap_skip(self)?;
        Ok(self)
    }
}

impl<'a, L: SkipFallback, S: LinkStore<L>, IS: io::IStream> Join<&'a mut L, &S> for Context<IS> where
{
    fn join(&mut self, store: &S, link: &'a mut L) -> Result<&mut Self> {
        //TODO: Move `skip` out of `join` and `skip` links explicitly.
        // That way it's easier to handle the case when the link is not found
        // and calling function can try to fetch and parse message for the link.
        //TODO: Implement a strategy (depth of recursion or max number of retries)
        // for such cases.
        link.unwrap_skip(self)?;
        let (mut s, i) = store.lookup(link)?;
        self.spongos.join(&mut s);
        Ok(self)
    }
}

/*
impl<'a, L, S: LinkStore<L>, IS: io::IStream> Join<&'a mut L, &S> for Context<IS> where
    Self: Skip<&'a mut L>,
{
    fn join(&mut self, store: &S, link: &'a mut L) -> Result<&mut Self> {
        self.skip(link)?;
        let (mut s, i) = store.lookup(link)?;
        self.spongos.join(&mut s);
        Ok(self)
    }
}
 */
