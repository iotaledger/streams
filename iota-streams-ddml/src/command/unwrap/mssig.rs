use anyhow::{
    ensure,
    Result,
};

use super::Context;
use crate::{
    command::{
        Commit,
        Mssig,
        Squeeze,
    },
    io,
    types::{
        External,
        MssHashSig,
        NTrytes,
    },
};
use iota_streams_core::{
    sponge::prp::PRP,
    tbits::{
        trinary,
        word::{
            IntTbitWord,
            SpongosTbitWord,
        },
        Tbits,
    },
};
use iota_streams_core_mss::signature::{
    mss,
    wots::Parameters as _,
};

/// Recover public key.
impl<'a, TW, F, IS: io::IStream<TW>, P> Mssig<&'a mut mss::PublicKey<TW, P>, &'a External<NTrytes<TW>>>
    for Context<TW, F, IS>
where
    TW: IntTbitWord + SpongosTbitWord + trinary::TritWord,
    F: PRP<TW>,
    P: mss::Parameters<TW>,
{
    fn mssig(&mut self, apk: &'a mut mss::PublicKey<TW, P>, hash: &'a External<NTrytes<TW>>) -> Result<&mut Self> {
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
        ensure!(d_skn.is_some(), "Failed to parse MSS signature skn: {:?}.", skn_slice);
        let (d, skn) = d_skn.unwrap();
        let n = P::apath_size(d);
        let wotsig_apath_slice = self.stream.try_advance(P::WotsParameters::SIGNATURE_SIZE + n)?;
        let (wotsig, apath) = wotsig_apath_slice.split_at(P::WotsParameters::SIGNATURE_SIZE);
        mss::recover_apk::<TW, P>(d, skn, ((hash.0).0).slice(), wotsig, apath, apk.tbits_mut().slice_mut());
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
    fn mssig(&mut self, pk: &'a mss::PublicKey<TW, P>, hash: &'a External<NTrytes<TW>>) -> Result<&mut Self> {
        let mut apk = mss::PublicKey::<TW, P>::default();
        self.mssig(&mut apk, hash)?;
        ensure!(apk == *pk, "Authenticity is violated, bad signature.");
        Ok(self)
    }
}

impl<'a, TW, F, IS: io::IStream<TW>, P> Mssig<&'a mut mss::PublicKey<TW, P>, MssHashSig> for Context<TW, F, IS>
where
    TW: IntTbitWord + SpongosTbitWord + trinary::TritWord,
    F: PRP<TW>,
    P: mss::Parameters<TW>,
{
    fn mssig(&mut self, apk: &'a mut mss::PublicKey<TW, P>, _hash: MssHashSig) -> Result<&mut Self> {
        let mut hash = External(NTrytes::<TW>(Tbits::<TW>::zero(P::HASH_SIZE)));
        self.squeeze(&mut hash)?.commit()?.mssig(apk, &hash)
    }
}

impl<'a, TW, F, IS: io::IStream<TW>, P> Mssig<&'a mss::PublicKey<TW, P>, MssHashSig> for Context<TW, F, IS>
where
    TW: IntTbitWord + SpongosTbitWord + trinary::TritWord,
    F: PRP<TW>,
    P: mss::Parameters<TW>,
{
    fn mssig(&mut self, pk: &'a mss::PublicKey<TW, P>, _hash: MssHashSig) -> Result<&mut Self> {
        let mut hash = External(NTrytes::<TW>(Tbits::<TW>::zero(P::HASH_SIZE)));
        self.squeeze(&mut hash)?.commit()?.mssig(pk, &hash)
    }
}
