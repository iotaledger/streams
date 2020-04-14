use failure::Fallible;

use super::Context;
use crate::{
    command::Ntrukem,
    types::NTrytes,
};
use iota_streams_core::tbits::word::BasicTbitWord;
use iota_streams_core_ntru::key_encapsulation::ntru;

/// Sizeof encapsulated secret is fixed.
impl<TW, F> Ntrukem<&ntru::PublicKey<TW, F>, &NTrytes<TW>> for Context<TW, F>
where
    TW: BasicTbitWord,
{
    fn ntrukem(&mut self, _key: &ntru::PublicKey<TW, F>, _secret: &NTrytes<TW>) -> Fallible<&mut Self> {
        //TODO: Ensure key is valid.
        //TODO: ensure!(ntru::KEY_SIZE == (secret.0).size(), "Trit size of `external tryte secret[n]` to be encapsulated with NTRU must be equal {} trits.", ntru::KEY_SIZE);
        self.size += ntru::EKEY_SIZE;
        Ok(self)
    }
}
