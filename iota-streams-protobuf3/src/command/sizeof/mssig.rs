use failure::{
    ensure,
    Fallible,
};

use super::Context;
use crate::{
    command::Mssig,
    types::{
        External,
        Mac,
        MssHashSig,
        NTrytes,
    },
};
use iota_streams_core::tbits::word::{
    IntTbitWord,
    SpongosTbitWord,
};
use iota_streams_core_mss::signature::mss;

/// Signature size depends on Merkle tree height.
impl<TW, F, P> Mssig<&mss::PrivateKey<TW, P>, &External<NTrytes<TW>>> for Context<TW, F>
where
    TW: IntTbitWord + SpongosTbitWord,
    P: mss::Parameters<TW>,
{
    fn mssig(&mut self, sk: &mss::PrivateKey<TW, P>, hash: &External<NTrytes<TW>>) -> Fallible<&mut Self> {
        ensure!(
            P::HASH_SIZE == ((hash.0).0).size(),
            "Trit size of `external tryte hash[n]` to be signed with MSS must be equal {} trits.",
            P::HASH_SIZE
        );
        ensure!(
            sk.private_keys_left() > 0,
            "All WOTS private keys in MSS Merkle tree have been exhausted, nothing to sign hash with."
        );
        self.size += P::signature_size(sk.height());
        Ok(self)
    }
}

impl<TW, F, P> Mssig<&mss::PrivateKey<TW, P>, &External<Mac>> for Context<TW, F>
where
    TW: IntTbitWord + SpongosTbitWord,
    P: mss::Parameters<TW>,
{
    fn mssig(&mut self, sk: &mss::PrivateKey<TW, P>, hash: &External<Mac>) -> Fallible<&mut Self> {
        ensure!(
            P::HASH_SIZE == (hash.0).0,
            "Trit size of `external tryte hash[n]` to be signed with MSS must be equal {} trits.",
            P::HASH_SIZE
        );
        ensure!(
            sk.private_keys_left() > 0,
            "All WOTS private keys in MSS Merkle tree have been exhausted, nothing to sign hash with."
        );
        self.size += P::signature_size(sk.height());
        Ok(self)
    }
}

impl<TW, F, P> Mssig<&mss::PrivateKey<TW, P>, MssHashSig> for Context<TW, F>
where
    TW: IntTbitWord + SpongosTbitWord,
    P: mss::Parameters<TW>,
{
    fn mssig(&mut self, sk: &mss::PrivateKey<TW, P>, _hash: MssHashSig) -> Fallible<&mut Self> {
        // Squeeze external and commit cost nothing in the stream.
        self.size += P::signature_size(sk.height());
        Ok(self)
    }
}
