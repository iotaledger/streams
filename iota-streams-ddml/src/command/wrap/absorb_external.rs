use crypto::{
    keys::x25519,
    signatures::ed25519,
};

use iota_streams_core::{
    sponge::prp::PRP,
    Result,
};

use super::Context;
use crate::{
    command::Absorb,
    io,
    types::{
        AbsorbExternalFallback,
        ArrayLength,
        External,
        Fallback,
        NBytes,
        Size,
        Uint16,
        Uint32,
        Uint64,
        Uint8,
    },
};

impl<'a, T: 'a, F: PRP, OS: io::OStream> Absorb<&'a External<T>> for Context<F, OS>
where
    Self: Absorb<External<&'a T>>,
{
    fn absorb(&mut self, external: &'a External<T>) -> Result<&mut Self> {
        self.absorb(External(&external.0))
    }
}

impl<F: PRP, OS: io::OStream> Absorb<External<Uint8>> for Context<F, OS> {
    fn absorb(&mut self, u: External<Uint8>) -> Result<&mut Self> {
        self.spongos.absorb(u.into_inner().to_bytes());
        Ok(self)
    }
}

impl<F: PRP, OS: io::OStream> Absorb<External<Uint16>> for Context<F, OS> {
    fn absorb(&mut self, u: External<Uint16>) -> Result<&mut Self> {
        self.spongos.absorb(u.into_inner().to_bytes());
        Ok(self)
    }
}

impl<F: PRP, OS: io::OStream> Absorb<External<Uint32>> for Context<F, OS> {
    fn absorb(&mut self, u: External<Uint32>) -> Result<&mut Self> {
        self.spongos.absorb(u.into_inner().to_bytes());
        Ok(self)
    }
}

impl<F: PRP, OS: io::OStream> Absorb<External<Uint64>> for Context<F, OS> {
    fn absorb(&mut self, u: External<Uint64>) -> Result<&mut Self> {
        self.spongos.absorb(u.into_inner().to_bytes());
        Ok(self)
    }
}

impl<F: PRP, OS: io::OStream> Absorb<External<Size>> for Context<F, OS> {
    fn absorb(&mut self, size: External<Size>) -> Result<&mut Self> {
        size.into_inner().encode(|byte| {
            self.spongos.absorb(&[byte]);
            Ok(())
        })?;
        Ok(self)
    }
}

impl<'a, F: PRP, N: ArrayLength<u8>, OS: io::OStream> Absorb<External<&'a NBytes<N>>> for Context<F, OS> {
    fn absorb(&mut self, bytes: External<&'a NBytes<N>>) -> Result<&mut Self> {
        self.spongos.absorb(bytes.into_inner());
        Ok(self)
    }
}

impl<'a, F: PRP, OS: io::OStream> Absorb<External<&'a ed25519::PublicKey>> for Context<F, OS> {
    fn absorb(&mut self, public_key: External<&'a ed25519::PublicKey>) -> Result<&mut Self> {
        self.spongos.absorb(public_key.into_inner());
        Ok(self)
    }
}

impl<'a, F: PRP, OS: io::OStream> Absorb<External<&'a x25519::PublicKey>> for Context<F, OS> {
    fn absorb(&mut self, public_key: External<&'a x25519::PublicKey>) -> Result<&mut Self> {
        self.spongos.absorb(public_key.into_inner());
        Ok(self)
    }
}

impl<'a, F, T: 'a + AbsorbExternalFallback<F>, OS: io::OStream> Absorb<External<Fallback<&'a T>>> for Context<F, OS> {
    fn absorb(&mut self, val: External<Fallback<&'a T>>) -> Result<&mut Self> {
        val.into_inner().into_inner().wrap_absorb_external(self)?;
        Ok(self)
    }
}
