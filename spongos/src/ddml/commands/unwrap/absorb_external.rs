use anyhow::Result;
use crypto::{
    keys::x25519,
    signatures::ed25519,
};
use generic_array::ArrayLength;

use crate::{
    core::prp::PRP,
    ddml::{
        commands::{
            unwrap::Context,
            Absorb,
        },
        io,
        modifiers::External,
        types::{
            NBytes,
            Size,
            Uint16,
            Uint32,
            Uint64,
            Uint8,
        },
    },
};

impl<F: PRP, IS> Absorb<External<Uint8>> for Context<F, IS> {
    fn absorb(&mut self, u: External<Uint8>) -> Result<&mut Self> {
        self.spongos.absorb(u.into_inner().to_bytes());
        Ok(self)
    }
}

impl<F: PRP, IS> Absorb<External<Uint16>> for Context<F, IS> {
    fn absorb(&mut self, u: External<Uint16>) -> Result<&mut Self> {
        self.spongos.absorb(u.into_inner().to_bytes());
        Ok(self)
    }
}

impl<F: PRP, IS> Absorb<External<Uint32>> for Context<F, IS> {
    fn absorb(&mut self, u: External<Uint32>) -> Result<&mut Self> {
        self.spongos.absorb(u.into_inner().to_bytes());
        Ok(self)
    }
}

impl<F: PRP, IS> Absorb<External<Uint64>> for Context<F, IS> {
    fn absorb(&mut self, u: External<Uint64>) -> Result<&mut Self> {
        self.spongos.absorb(u.into_inner().to_bytes());
        Ok(self)
    }
}

impl<F: PRP, IS> Absorb<External<Size>> for Context<F, IS> {
    fn absorb(&mut self, size: External<Size>) -> Result<&mut Self> {
        size.into_inner().encode(|byte| {
            self.spongos.absorb(&[byte]);
            Ok(())
        })?;
        Ok(self)
    }
}

impl<'a, F: PRP, N: ArrayLength<u8>, IS> Absorb<External<&'a NBytes<N>>> for Context<F, IS> {
    fn absorb(&mut self, bytes: External<&'a NBytes<N>>) -> Result<&mut Self> {
        self.spongos.absorb(bytes);
        Ok(self)
    }
}

impl<'a, F: PRP, IS> Absorb<External<&'a ed25519::PublicKey>> for Context<F, IS> {
    fn absorb(&mut self, public_key: External<&'a ed25519::PublicKey>) -> Result<&mut Self> {
        self.spongos.absorb(public_key);
        Ok(self)
    }
}

impl<'a, F: PRP, IS> Absorb<External<&'a x25519::PublicKey>> for Context<F, IS> {
    fn absorb(&mut self, public_key: External<&'a x25519::PublicKey>) -> Result<&mut Self> {
        self.spongos.absorb(public_key);
        Ok(self)
    }
}

// TODO: REMOVE
// impl<'a, F, T: 'a + AbsorbExternalFallback<F>, IS: io::IStream> Absorb<External<Fallback<&'a T>>> for Context<F, IS>
// {     fn absorb(&mut self, val: External<Fallback<&'a T>>) -> Result<&mut Self> {
//         val.into_inner().into_inner().unwrap_absorb_external(self)?;
//         Ok(self)
//     }
// }

// Implement &External<T> for any External<&T> implementation
impl<'a, T, F, IS> Absorb<&'a External<T>> for Context<F, IS>
where
    Self: Absorb<External<&'a T>>,
{
    fn absorb(&mut self, external: &'a External<T>) -> Result<&mut Self> {
        self.absorb(External::new(external.inner()))
    }
}
