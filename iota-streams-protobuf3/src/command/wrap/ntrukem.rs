use failure::Fallible;

use super::Context;
use crate::{
    command::Ntrukem,
    io,
    types::NTrytes,
};
use iota_streams_core::{
    prng,
    sponge::prp::PRP,
    tbits::{
        trinary,
        word::SpongosTbitWord,
        Tbits,
    },
};
use iota_streams_core_ntru::key_encapsulation::ntru;

impl<'a, TW, F, OS: io::OStream<TW>, G>
    Ntrukem<(&'a ntru::PublicKey<TW, F>, &'a prng::Prng<TW, G>, &'a Tbits<TW>), &'a NTrytes<TW>> for Context<TW, F, OS>
where
    TW: SpongosTbitWord + trinary::TritWord,
    F: PRP<TW>,
    G: PRP<TW> + Clone + Default,
{
    fn ntrukem(
        &mut self,
        key: (&'a ntru::PublicKey<TW, F>, &'a prng::Prng<TW, G>, &'a Tbits<TW>),
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
