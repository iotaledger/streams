use failure::{
    ensure,
    Fallible,
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
use iota_streams_core_mss::signature::mss;

impl<'a, TW, F, OS: io::OStream<TW>, P> Mssig<&'a mss::PrivateKey<TW, P>, &'a External<NTrytes<TW>>>
    for Context<TW, F, OS>
where
    TW: IntTbitWord + SpongosTbitWord + trinary::TritWord,
    F: PRP<TW>,
    P: mss::Parameters<TW>,
{
    fn mssig(&mut self, sk: &'a mss::PrivateKey<TW, P>, hash: &'a External<NTrytes<TW>>) -> Fallible<&mut Self> {
        ensure!(
            P::HASH_SIZE == ((hash.0).0).size(),
            "Trit size of `external tryte hash[n]` to be signed with MSS must be equal {} trits.",
            P::HASH_SIZE
        );
        ensure!(
            sk.private_keys_left() > 0,
            "All WOTS private keys in MSS Merkle tree have been exhausted, nothing to sign hash with."
        );
        let sig_slice = self.stream.try_advance(P::signature_size(sk.height()))?;
        sk.sign(((hash.0).0).slice(), sig_slice);
        Ok(self)
    }
}

impl<'a, TW, F, OS: io::OStream<TW>, P> Mssig<&'a mut mss::PrivateKey<TW, P>, &'a External<NTrytes<TW>>>
    for Context<TW, F, OS>
where
    TW: IntTbitWord + SpongosTbitWord + trinary::TritWord,
    F: PRP<TW>,
    P: mss::Parameters<TW>,
{
    fn mssig(&mut self, sk: &'a mut mss::PrivateKey<TW, P>, hash: &'a External<NTrytes<TW>>) -> Fallible<&mut Self> {
        // Force convert to `&self` with a smaller life-time.
        <Self as Mssig<&'_ mss::PrivateKey<TW, P>, &'_ External<NTrytes<TW>>>>::mssig(self, sk, hash)?;
        sk.next();
        Ok(self)
    }
}

impl<'a, TW, F, OS: io::OStream<TW>, P> Mssig<&'a mss::PrivateKey<TW, P>, MssHashSig> for Context<TW, F, OS>
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

impl<'a, TW, F, OS: io::OStream<TW>, P> Mssig<&'a mut mss::PrivateKey<TW, P>, MssHashSig> for Context<TW, F, OS>
where
    TW: IntTbitWord + SpongosTbitWord + trinary::TritWord,
    F: PRP<TW>,
    P: mss::Parameters<TW>,
{
    fn mssig(&mut self, sk: &'a mut mss::PrivateKey<TW, P>, _hash: MssHashSig) -> Fallible<&mut Self> {
        let mut hash = External(NTrytes(Tbits::<TW>::zero(P::HASH_SIZE)));
        self.squeeze(&mut hash)?.commit()?.mssig(sk, &hash)
    }
}
