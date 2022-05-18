use anyhow::Result;
use crypto::{keys::x25519, signatures::ed25519};

use crate::{
    core::prp::PRP,
    ddml::{
        commands::{unwrap::Context, Absorb},
        modifiers::External,
        types::{NBytes, Size, Uint16, Uint32, Uint64, Uint8},
    },
};

impl<F: PRP, IS> Absorb<External<Uint8>> for Context<IS, F> {
    fn absorb(&mut self, u: External<Uint8>) -> Result<&mut Self> {
        self.spongos.absorb(u.into_inner().to_bytes());
        Ok(self)
    }
}

impl<F: PRP, IS> Absorb<External<Uint16>> for Context<IS, F> {
    fn absorb(&mut self, u: External<Uint16>) -> Result<&mut Self> {
        self.spongos.absorb(u.into_inner().to_bytes());
        Ok(self)
    }
}

impl<F: PRP, IS> Absorb<External<Uint32>> for Context<IS, F> {
    fn absorb(&mut self, u: External<Uint32>) -> Result<&mut Self> {
        self.spongos.absorb(u.into_inner().to_bytes());
        Ok(self)
    }
}

impl<F: PRP, IS> Absorb<External<Uint64>> for Context<IS, F> {
    fn absorb(&mut self, u: External<Uint64>) -> Result<&mut Self> {
        self.spongos.absorb(u.into_inner().to_bytes());
        Ok(self)
    }
}

impl<F: PRP, IS> Absorb<External<Size>> for Context<IS, F> {
    fn absorb(&mut self, size: External<Size>) -> Result<&mut Self> {
        size.into_inner().encode(|byte| {
            self.spongos.absorb(&[byte]);
            Ok(())
        })?;
        Ok(self)
    }
}

impl<'a, F: PRP, T: AsRef<[u8]>, IS> Absorb<External<&'a NBytes<T>>> for Context<IS, F> {
    fn absorb(&mut self, bytes: External<&'a NBytes<T>>) -> Result<&mut Self> {
        self.spongos.absorb(bytes);
        Ok(self)
    }
}

impl<'a, F: PRP, IS> Absorb<External<&'a ed25519::PublicKey>> for Context<IS, F> {
    fn absorb(&mut self, public_key: External<&'a ed25519::PublicKey>) -> Result<&mut Self> {
        self.spongos.absorb(public_key);
        Ok(self)
    }
}

impl<'a, F: PRP, IS> Absorb<External<&'a x25519::PublicKey>> for Context<IS, F> {
    fn absorb(&mut self, public_key: External<&'a x25519::PublicKey>) -> Result<&mut Self> {
        self.spongos.absorb(public_key);
        Ok(self)
    }
}
