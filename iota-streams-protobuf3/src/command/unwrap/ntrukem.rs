use anyhow::{
    ensure,
    Result,
};

use super::Context;
use crate::{
    command::Ntrukem,
    io,
    types::NTrytes,
};
use iota_streams_core::{
    sponge::prp::PRP,
    tbits::{
        trinary,
        word::SpongosTbitWord,
    },
};
use iota_streams_core_ntru::key_encapsulation::ntru;

impl<'a, TW, F, IS: io::IStream<TW>> Ntrukem<&'a ntru::PrivateKey<TW, F>, &'a mut NTrytes<TW>> for Context<TW, F, IS>
where
    TW: SpongosTbitWord + trinary::TritWord,
    F: PRP<TW>,
{
    fn ntrukem(&mut self, sk: &'a ntru::PrivateKey<TW, F>, secret: &'a mut NTrytes<TW>) -> Result<&mut Self> {
        //TODO: ensure!(ntru::KEY_SIZE == (secret.0).size(), "Trit size of `external tryte secret[n]` to be encapsulated with NTRU must be equal {} trits.", ntru::KEY_SIZE);

        let ekey_slice = self.stream.try_advance(ntru::EKEY_SIZE)?;
        ensure!(
            sk.decrypt_with_spongos(&mut self.spongos, ekey_slice, (secret.0).slice_mut()),
            "Failed to decapsulate secret."
        );
        Ok(self)
    }
}
