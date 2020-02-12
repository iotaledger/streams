use failure::{ensure};
use std::convert::AsMut;
use std::iter;
use std::mem;

use iota_mam_core::trits::{self, word::BasicTritWord, DefaultTritWord, Trits, TritSlice, TritSliceMut};
use iota_mam_core::spongos::*;
use iota_mam_core::prng;
use iota_mam_core::signature::mss;
use iota_mam_core::key_encapsulation::ntru;

use crate::io;
use crate::Result;
use crate::command::*;
use crate::types::*;

#[derive(Debug)]
pub struct Context<OS> {
    pub spongos: Spongos,
    pub stream: OS,
}

impl<OS> Context<OS> {
    pub fn new(stream: OS) -> Self {
        Self {
            spongos: Spongos::init(),
            stream: stream,
        }
    }
}

/// Helper trait for wrapping (encoding/absorbing) trint3s.
pub(crate) trait Wrap {
    fn wrap3(&mut self, trint3: Trint3) -> Result<&mut Self>;
    fn wrapn(&mut self, trits: TritSlice) -> Result<&mut Self>;
}

/// Helper function for wrapping (encoding/absorbing) size values.
pub(crate) fn wrap_size<'a, Ctx: Wrap>(ctx: &'a mut Ctx, size: Size) -> Result<&'a mut Ctx> where
{
    let d = size_trytes(size.0);
    ctx.wrap3(Trint3(d as i8))?;

    let mut n = size.0;
    for _ in 0..d {
        let (r, q) = trits::mods3_usize(n);
        ctx.wrap3(r)?;
        n = q;
    }
    Ok(ctx)
}

struct AbsorbContext<OS> {
    ctx: Context<OS>,
}
impl<OS> AsMut<AbsorbContext<OS>> for Context<OS> {
    fn as_mut<'a>(&'a mut self) -> &'a mut AbsorbContext<OS> {
        unsafe { mem::transmute::<&'a mut Context<OS>, &'a mut AbsorbContext<OS>>(self) }
    }
}
impl<OS> AsMut<Context<OS>> for AbsorbContext<OS> {
    fn as_mut<'a>(&'a mut self) -> &'a mut Context<OS> {
        unsafe { mem::transmute::<&'a mut AbsorbContext<OS>, &'a mut Context<OS>>(self) }
    }
}

impl<OS: io::OStream> Wrap for AbsorbContext<OS> {
    fn wrap3(&mut self, trint3: Trint3) -> Result<&mut Self> {
        let slice = self.ctx.stream.try_advance(3)?;
        slice.put3(trint3);
        self.ctx.spongos.absorb(slice.as_const());
        Ok(self)
    }
    fn wrapn(&mut self, trits: TritSlice) -> Result<&mut Self> {
        self.ctx.spongos.absorb(trits);
        let slice = self.ctx.stream.try_advance(trits.size())?;
        trits.copy(slice);
        Ok(self)
    }
}

fn wrap_absorb_trint3<'a, OS: io::OStream>(ctx: &'a mut AbsorbContext<OS>, trint3: Trint3) -> Result<&'a mut AbsorbContext<OS>> where
{
    ctx.wrap3(trint3)
}
fn wrap_absorb_size<'a, OS: io::OStream>(ctx: &'a mut AbsorbContext<OS>, size: Size) -> Result<&'a mut AbsorbContext<OS>> where
{
    wrap_size(ctx, size)
}
fn wrap_absorb_trits<'a, OS: io::OStream>(ctx: &'a mut AbsorbContext<OS>, trits: TritSlice) -> Result<&'a mut AbsorbContext<OS>> where
{
    ctx.wrapn(trits)
}

impl<'a, OS: io::OStream> Absorb<&'a Trint3> for Context<OS> {
    fn absorb(&mut self, trint3: &'a Trint3) -> Result<&mut Self> {
        Ok(wrap_absorb_trint3(self.as_mut(), *trint3)?.as_mut())
    }
}

impl<OS: io::OStream> Absorb<Trint3> for Context<OS> {
    fn absorb(&mut self, trint3: Trint3) -> Result<&mut Self> {
        self.absorb(&trint3)
    }
}

impl<'a, OS: io::OStream> Absorb<&'a Size> for Context<OS> {
    fn absorb(&mut self, size: &'a Size) -> Result<&mut Self> {
        Ok(wrap_absorb_size(self.as_mut(), *size)?.as_mut())
    }
}

impl<OS: io::OStream> Absorb<Size> for Context<OS> {
    fn absorb(&mut self, size: Size) -> Result<&mut Self> {
        self.absorb(&size)
    }
}

impl<'a, OS: io::OStream> Absorb<&'a NTrytes> for Context<OS> {
    fn absorb(&mut self, ntrytes: &'a NTrytes) -> Result<&mut Self> {
        Ok(wrap_absorb_trits(self.as_mut(), (ntrytes.0).slice())?.as_mut())
    }
}

impl<'a, OS: io::OStream> Absorb<&'a Trytes> for Context<OS> {
    fn absorb(&mut self, trytes: &'a Trytes) -> Result<&mut Self> {
        self.absorb(Size((trytes.0).size() / 3))?;
        Ok(wrap_absorb_trits(self.as_mut(), (trytes.0).slice())?.as_mut())
    }
}

impl<'a, OS: io::OStream> Absorb<&'a mss::PublicKey> for Context<OS> {
    fn absorb(&mut self, pk: &'a mss::PublicKey) -> Result<&mut Self> {
        ensure!(pk.pk.size() == mss::PK_SIZE);
        Ok(wrap_absorb_trits(self.as_mut(), pk.pk.slice())?.as_mut())
    }
}

impl<'a, OS: io::OStream> Absorb<&'a ntru::PublicKey> for Context<OS> {
    fn absorb(&mut self, pk: &'a ntru::PublicKey) -> Result<&mut Self> {
        ensure!(pk.pk.size() == ntru::PK_SIZE);
        Ok(wrap_absorb_trits(self.as_mut(), pk.pk.slice())?.as_mut())
    }
}


struct AbsorbExternalContext<OS> {
    ctx: Context<OS>,
}
impl<OS> AsMut<AbsorbExternalContext<OS>> for Context<OS> {
    fn as_mut<'a>(&'a mut self) -> &'a mut AbsorbExternalContext<OS> {
        unsafe { mem::transmute::<&'a mut Context<OS>, &'a mut AbsorbExternalContext<OS>>(self) }
    }
}
impl<OS> AsMut<Context<OS>> for AbsorbExternalContext<OS> {
    fn as_mut<'a>(&'a mut self) -> &'a mut Context<OS> {
        unsafe { mem::transmute::<&'a mut AbsorbExternalContext<OS>, &'a mut Context<OS>>(self) }
    }
}

impl<OS: io::OStream> Wrap for AbsorbExternalContext<OS> {
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

fn wrap_absorb_external_trint3<'a, OS: io::OStream>(ctx: &'a mut AbsorbExternalContext<OS>, trint3: Trint3) -> Result<&'a mut AbsorbExternalContext<OS>> where
{
    ctx.wrap3(trint3)
}
fn wrap_absorb_external_size<'a, OS: io::OStream>(ctx: &'a mut AbsorbExternalContext<OS>, size: Size) -> Result<&'a mut AbsorbExternalContext<OS>> where
{
    wrap_size(ctx, size)
}
fn wrap_absorb_external_trits<'a, OS: io::OStream>(ctx: &'a mut AbsorbExternalContext<OS>, trits: TritSlice) -> Result<&'a mut AbsorbExternalContext<OS>> where
{
    ctx.wrapn(trits)
}

impl<'a, T: 'a, OS: io::OStream> Absorb<&'a External<T>> for Context<OS> where
    Self: Absorb<External<&'a T>>
{
    fn absorb(&mut self, external: &'a External<T>) -> Result<&mut Self> {
        self.absorb(External(&external.0))
    }
}

impl<'a, OS: io::OStream> Absorb<External<&'a Size>> for Context<OS> {
    fn absorb(&mut self, size: External<&'a Size>) -> Result<&mut Self> {
        Ok(wrap_absorb_external_size(self.as_mut(), *size.0)?.as_mut())
    }
}

impl<OS: io::OStream> Absorb<External<Size>> for Context<OS> {
    fn absorb(&mut self, size: External<Size>) -> Result<&mut Self> {
        self.absorb(&size)
    }
}

impl<'a, OS: io::OStream> Absorb<External<&'a NTrytes>> for Context<OS> {
    fn absorb(&mut self, external_ntrytes: External<&'a NTrytes>) -> Result<&mut Self> {
        Ok(wrap_absorb_external_trits(self.as_mut(), ((external_ntrytes.0).0).slice())?.as_mut())
    }
}

impl<'a, OS: io::OStream> Absorb<External<&'a mss::PublicKey>> for Context<OS> {
    fn absorb(&mut self, pk: External<&'a mss::PublicKey>) -> Result<&mut Self> {
        ensure!((pk.0).pk.size() == mss::PK_SIZE);
        Ok(wrap_absorb_trits(self.as_mut(), (pk.0).pk.slice())?.as_mut())
    }
}

impl<'a, OS: io::OStream> Absorb<External<&'a ntru::PublicKey>> for Context<OS> {
    fn absorb(&mut self, pk: External<&'a ntru::PublicKey>) -> Result<&mut Self> {
        ensure!((pk.0).pk.size() == ntru::PK_SIZE);
        Ok(wrap_absorb_trits(self.as_mut(), (pk.0).pk.slice())?.as_mut())
    }
}


/// This is just an external tag or hash value to-be-signed.
impl<'a, OS> Squeeze<&'a mut External<NTrytes>> for Context<OS> {
    fn squeeze(&mut self, external_ntrytes: &'a mut External<NTrytes>) -> Result<&mut Self> {
        self.spongos.squeeze(((external_ntrytes.0).0).slice_mut());
        Ok(self)
    }
}

/// This is just an external tag or hash value to-be-signed.
impl<'a, OS> Squeeze<External<&'a mut NTrytes>> for Context<OS> {
    fn squeeze(&mut self, external_ntrytes: External<&'a mut NTrytes>) -> Result<&mut Self> {
        self.spongos.squeeze(((external_ntrytes.0).0).slice_mut());
        Ok(self)
    }
}

/// External values are not encoded.
impl<'a, OS: io::OStream> Squeeze<&'a Mac> for Context<OS> {
    fn squeeze(&mut self, mac: &'a Mac) -> Result<&mut Self> {
        self.spongos.squeeze(self.stream.try_advance(mac.0)?);
        Ok(self)
    }
}


struct MaskContext<OS> {
    ctx: Context<OS>,
}
impl<OS> AsMut<MaskContext<OS>> for Context<OS> {
    fn as_mut<'a>(&'a mut self) -> &'a mut MaskContext<OS> {
        unsafe { mem::transmute::<&'a mut Context<OS>, &'a mut MaskContext<OS>>(self) }
    }
}
impl<OS> AsMut<Context<OS>> for MaskContext<OS> {
    fn as_mut<'a>(&'a mut self) -> &'a mut Context<OS> {
        unsafe { mem::transmute::<&'a mut MaskContext<OS>, &'a mut Context<OS>>(self) }
    }
}

impl<OS: io::OStream> Wrap for MaskContext<OS> {
    fn wrap3(&mut self, trint3: Trint3) -> Result<&mut Self> {
        let slice = self.ctx.stream.try_advance(3)?;
        slice.put3(trint3);
        self.ctx.spongos.encr_mut(slice);
        Ok(self)
    }
    fn wrapn(&mut self, trits: TritSlice) -> Result<&mut Self> {
        let slice = self.ctx.stream.try_advance(trits.size())?;
        self.ctx.spongos.encr(trits, slice);
        Ok(self)
    }
}

fn wrap_mask_trint3<'a, OS: io::OStream>(ctx: &'a mut MaskContext<OS>, trint3: Trint3) -> Result<&'a mut MaskContext<OS>> where
{
    ctx.wrap3(trint3)
}
fn wrap_mask_size<'a, OS: io::OStream>(ctx: &'a mut MaskContext<OS>, size: Size) -> Result<&'a mut MaskContext<OS>> where
{
    wrap_size(ctx, size)
}
fn wrap_mask_trits<'a, OS: io::OStream>(ctx: &'a mut MaskContext<OS>, trits: TritSlice) -> Result<&'a mut MaskContext<OS>> where
{
    ctx.wrapn(trits)
}

impl<'a, OS: io::OStream> Mask<&'a Trint3> for Context<OS> {
    fn mask(&mut self, trint3: &'a Trint3) -> Result<&mut Self> {
        Ok(wrap_mask_trint3(self.as_mut(), *trint3)?.as_mut())
    }
}

impl<'a, OS: io::OStream> Mask<&'a Size> for Context<OS> {
    fn mask(&mut self, size: &'a Size) -> Result<&mut Self> {
        Ok(wrap_mask_size(self.as_mut(), *size)?.as_mut())
    }
}

impl<'a, OS: io::OStream> Mask<&'a NTrytes> for Context<OS> {
    fn mask(&mut self, ntrytes: &'a NTrytes) -> Result<&mut Self> {
        Ok(wrap_mask_trits(self.as_mut(), (ntrytes.0).slice())?.as_mut())
    }
}

impl<'a, OS: io::OStream> Mask<&'a Trytes> for Context<OS> {
    fn mask(&mut self, trytes: &'a Trytes) -> Result<&mut Self> {
        ensure!((trytes.0).size() % 3 == 0, "Trit size of `trytes` must be a multiple of 3: {}.", (trytes.0).size());
        let size = Size((trytes.0).size() / 3);
        self.mask(&size)?;
        Ok(wrap_mask_trits(self.as_mut(), (trytes.0).slice())?.as_mut())
    }
}


struct SkipContext<OS> {
    ctx: Context<OS>,
}
impl<OS> AsMut<SkipContext<OS>> for Context<OS> {
    fn as_mut<'a>(&'a mut self) -> &'a mut SkipContext<OS> {
        unsafe { mem::transmute::<&'a mut Context<OS>, &'a mut SkipContext<OS>>(self) }
    }
}
impl<OS> AsMut<Context<OS>> for SkipContext<OS> {
    fn as_mut<'a>(&'a mut self) -> &'a mut Context<OS> {
        unsafe { mem::transmute::<&'a mut SkipContext<OS>, &'a mut Context<OS>>(self) }
    }
}

impl<OS: io::OStream> Wrap for SkipContext<OS> {
    fn wrap3(&mut self, trint3: Trint3) -> Result<&mut Self> {
        let slice = self.ctx.stream.try_advance(3)?;
        slice.put3(trint3);
        Ok(self)
    }
    fn wrapn(&mut self, trits: TritSlice) -> Result<&mut Self> {
        let slice = self.ctx.stream.try_advance(trits.size())?;
        trits.copy(slice);
        Ok(self)
    }
}

fn wrap_skip_trint3<'a, OS: io::OStream>(ctx: &'a mut SkipContext<OS>, trint3: Trint3) -> Result<&'a mut SkipContext<OS>> where
{
    ctx.wrap3(trint3)
}
fn wrap_skip_size<'a, OS: io::OStream>(ctx: &'a mut SkipContext<OS>, size: Size) -> Result<&'a mut SkipContext<OS>> where
{
    wrap_size(ctx, size)
}
fn wrap_skip_trits<'a, OS: io::OStream>(ctx: &'a mut SkipContext<OS>, trits: TritSlice) -> Result<&'a mut SkipContext<OS>> where
{
    ctx.wrapn(trits)
}

impl<'a, OS: io::OStream> Skip<&'a Trint3> for Context<OS> {
    fn skip(&mut self, trint3: &'a Trint3) -> Result<&mut Self> {
        Ok(wrap_skip_trint3(self.as_mut(), *trint3)?.as_mut())
    }
}

impl<OS: io::OStream> Skip<Trint3> for Context<OS> {
    fn skip(&mut self, val: Trint3) -> Result<&mut Self> {
        self.skip(&val)
    }
}

impl<'a, OS: io::OStream> Skip<&'a Size> for Context<OS> {
    fn skip(&mut self, size: &'a Size) -> Result<&mut Self> {
        Ok(wrap_skip_size(self.as_mut(), *size)?.as_mut())
    }
}

impl<OS: io::OStream> Skip<Size> for Context<OS> {
    fn skip(&mut self, val: Size) -> Result<&mut Self> {
        self.skip(&val)
    }
}

impl<'a, OS: io::OStream> Skip<&'a NTrytes> for Context<OS> {
    fn skip(&mut self, ntrytes: &'a NTrytes) -> Result<&mut Self> {
        Ok(wrap_skip_trits(self.as_mut(), (ntrytes.0).slice())?.as_mut())
    }
}

impl<'a, OS: io::OStream> Skip<&'a Trytes> for Context<OS> {
    fn skip(&mut self, trytes: &'a Trytes) -> Result<&mut Self> {
        self.skip(Size((trytes.0).size() / 3))?;
        Ok(wrap_skip_trits(self.as_mut(), (trytes.0).slice())?.as_mut())
    }
}

/// Commit Spongos.
impl<OS> Commit for Context<OS> {
    fn commit(&mut self) -> Result<&mut Self> {
        self.spongos.commit();
        Ok(self)
    }
}

impl<'a, OS: io::OStream> Mssig<&'a mss::PrivateKey, &'a External<NTrytes>> for Context<OS> {
    fn mssig(&mut self, sk: &'a mss::PrivateKey, hash: &'a External<NTrytes>) -> Result<&mut Self> {
        ensure!(mss::HASH_SIZE == ((hash.0).0).size(), "Trit size of `external tryte hash[n]` to be signed with MSS must be equal {} trits.", mss::HASH_SIZE);
        ensure!(sk.skn_left() > 0, "All WOTS private keys in MSS Merkle tree have been exhausted, nothing to sign hash with.");
        let sig_slice = self.stream.try_advance(mss::sig_size(sk.height()))?;
        sk.sign(((hash.0).0).slice(), sig_slice);
        Ok(self)
    }
}

impl<'a, OS: io::OStream> Mssig<&'a mut mss::PrivateKey, &'a External<NTrytes>> for Context<OS> {
    fn mssig(&mut self, sk: &'a mut mss::PrivateKey, hash: &'a External<NTrytes>) -> Result<&mut Self> {
        // Force convert to `&self` with a smaller life-time.
        <Self as Mssig<&'_ mss::PrivateKey, &'_ External<NTrytes>>>::mssig(self, sk, hash)?;
        sk.next();
        Ok(self)
    }
}

impl<'a, OS: io::OStream> Mssig<&'a mss::PrivateKey, MssHashSig> for Context<OS> {
    fn mssig(&mut self, sk: &'a mss::PrivateKey, _hash: MssHashSig) -> Result<&mut Self> {
        let mut hash = External(NTrytes(Trits::zero(mss::HASH_SIZE)));
        self
            .squeeze(&mut hash)?
            .commit()?
            .mssig(sk, &hash)
    }
}

impl<'a, OS: io::OStream> Mssig<&'a mut mss::PrivateKey, MssHashSig> for Context<OS> {
    fn mssig(&mut self, sk: &'a mut mss::PrivateKey, _hash: MssHashSig) -> Result<&mut Self> {
        let mut hash = External(NTrytes(Trits::zero(mss::HASH_SIZE)));
        self
            .squeeze(&mut hash)?
            .commit()?
            .mssig(sk, &hash)
    }
}

impl<'a, OS: io::OStream> Ntrukem<(&'a ntru::PublicKey, &'a prng::PRNG, &'a Trits), &'a NTrytes> for Context<OS> {
    fn ntrukem(&mut self, key: (&'a ntru::PublicKey, &'a prng::PRNG, &'a Trits), secret: &'a NTrytes) -> Result<&mut Self> {
        ensure!(ntru::KEY_SIZE == (secret.0).size(), "Trit size of `external tryte secret[n]` to be encapsulated with NTRU must be equal {} trits.", ntru::KEY_SIZE);

        let ekey_slice = self.stream.try_advance(ntru::EKEY_SIZE)?;
        (key.0).encr_with_s(&mut self.spongos, key.1, (key.2).slice(), (secret.0).slice(), ekey_slice);
        Ok(self)
    }
}


impl<F, OS: io::OStream> Fork<F> for Context<OS> where
    F: for<'a> FnMut(&'a mut Self) -> Result<&'a mut Self>
{
    fn fork(&mut self, mut cont: F) -> Result<&mut Self> {
        let mut saved_fork = self.spongos.fork();
        cont(self)?;
        self.spongos = saved_fork;
        Ok(self)
    }
}

impl<I, F, OS: io::OStream> Repeated<I, F> for Context<OS> where
    I: iter::Iterator,
    F: for<'a> FnMut(&'a mut Self, <I as iter::Iterator>::Item) -> Result<&'a mut Self>,
{
    fn repeated(&mut self, values_iter: I, mut value_handle: F) -> Result<&mut Self> {
        values_iter.fold(Ok(self), |rctx, item| -> Result<&mut Self> {
            match rctx {
                Ok(ctx) => value_handle(ctx, item),
                Err(e) => Err(e),
            }
        })
    }
}



impl<'a, T: 'a + AbsorbFallback, OS: io::OStream> Absorb<&'a T> for Context<OS> {
    fn absorb(&mut self, val: &'a T) -> Result<&mut Self> {
        val.wrap_absorb(self)?;
        Ok(self)
    }
}
impl<'a, T: 'a + AbsorbExternalFallback, OS: io::OStream> Absorb<External<&'a T>> for Context<OS> {
    fn absorb(&mut self, val: External<&'a T>) -> Result<&mut Self> {
        (val.0).wrap_absorb_external(self)?;
        Ok(self)
    }
}
impl<'a, T: 'a + SkipFallback, OS: io::OStream> Skip<&'a T> for Context<OS> {
    fn skip(&mut self, val: &'a T) -> Result<&mut Self> {
        val.wrap_skip(self)?;
        Ok(self)
    }
}

impl<'a, L: SkipFallback, S: LinkStore<L>, OS: io::OStream> Join<&'a L, &'a S> for Context<OS> {
    fn join(&mut self, store: &'a S, link: &'a L) -> Result<&mut Self> {
        let (mut s, i) = store.lookup(link)?;
        link.wrap_skip(self)?;
        self.spongos.join(&mut s);
        Ok(self)
    }
}

/*
impl<'a, L, S: LinkStore<L>, OS: io::OStream> Join<&'a L, &'a S> for Context<OS> where
    Self: Skip<&'a L>
{
    fn join(&mut self, store: &'a S, link: &'a L) -> Result<&mut Self> {
        let (mut s, i) = store.lookup(link)?;
        self.skip(link)?;
        self.spongos.join(&mut s);
        Ok(self)
    }
}
 */
