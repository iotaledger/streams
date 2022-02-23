use core::convert::TryInto;

use crypto::signatures::ed25519;

use iota_streams_core::{
    sponge::prp::PRP,
    try_or,
    Errors::SignatureMismatch,
    Result,
};

use super::Context;
use crate::{
    command::{
        Commit,
        Ed25519,
        Squeeze,
    },
    io,
    types::{
        External,
        HashSig,
        NBytes,
        U64,
    },
};

/// Recover public key.
impl<'a, F: PRP, IS: io::IStream> Ed25519<&'a ed25519::PublicKey, &'a External<NBytes<U64>>> for Context<F, IS> {
    fn ed25519(&mut self, public_key: &'a ed25519::PublicKey, hash: &'a External<NBytes<U64>>) -> Result<&mut Self> {
        let signature_bytes = self.stream.try_advance(ed25519::SIGNATURE_LENGTH)?;
        let signature = ed25519::Signature::from_bytes(signature_bytes.try_into()?);
        let is_valid = public_key.verify(&signature, hash.0.as_slice());
        try_or!(is_valid, SignatureMismatch)?;
        Ok(self)
    }
}

impl<'a, F: PRP, IS: io::IStream> Ed25519<&'a ed25519::PublicKey, HashSig> for Context<F, IS> {
    fn ed25519(&mut self, pk: &'a ed25519::PublicKey, _hash: HashSig) -> Result<&mut Self> {
        let mut hash = External(NBytes::<U64>::default());
        self.commit()?.squeeze(&mut hash)?.ed25519(pk, &hash)
    }
}
