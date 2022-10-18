use crypto::{keys::x25519, signatures::ed25519};

use crate::{
    core::prp::PRP,
    ddml::{
        commands::{wrap::Context, Absorb},
        modifiers::External,
        types::{NBytes, Size, Uint16, Uint32, Uint64, Uint8},
    },
    error::Result,
};

/// Absorbs a single byte encoded `Uint8` into [Spongos](`crate::core::spongos::Spongos`) state but
/// does not advance internal stream.
impl<F: PRP, OS> Absorb<External<Uint8>> for Context<OS, F> {
    fn absorb(&mut self, u: External<Uint8>) -> Result<&mut Self> {
        self.spongos.absorb(u.into_inner().to_bytes());
        Ok(self)
    }
}

/// Absorbs a two byte encoded `Uint16` into [Spongos](`crate::core::spongos::Spongos`) state but
/// does not advance internal stream.
impl<F: PRP, OS> Absorb<External<Uint16>> for Context<OS, F> {
    fn absorb(&mut self, u: External<Uint16>) -> Result<&mut Self> {
        self.spongos.absorb(u.into_inner().to_bytes());
        Ok(self)
    }
}

/// Absorbs a four byte encoded `Uint32` into [Spongos](`crate::core::spongos::Spongos`) state but
/// does not advance internal stream.
impl<F: PRP, OS> Absorb<External<Uint32>> for Context<OS, F> {
    fn absorb(&mut self, u: External<Uint32>) -> Result<&mut Self> {
        self.spongos.absorb(u.into_inner().to_bytes());
        Ok(self)
    }
}

/// Absorbs an eight byte encoded `Uint64` into [Spongos](`crate::core::spongos::Spongos`) state but
/// does not advance internal stream.
impl<F: PRP, OS> Absorb<External<Uint64>> for Context<OS, F> {
    fn absorb(&mut self, u: External<Uint64>) -> Result<&mut Self> {
        self.spongos.absorb(u.into_inner().to_bytes());
        Ok(self)
    }
}

/// Absorbs an `n` byte encoded [`Size`] into [Spongos](`crate::core::spongos::Spongos`) state but
/// does not advance internal stream.
impl<F: PRP, OS> Absorb<External<Size>> for Context<OS, F> {
    fn absorb(&mut self, size: External<Size>) -> Result<&mut Self> {
        size.into_inner().encode(|byte| {
            self.spongos.absorb(&[byte]);
            Ok(())
        })?;
        Ok(self)
    }
}

/// Absorbs an `n` byte encoded [`NBytes`] into [Spongos](`crate::core::spongos::Spongos`) state but
/// does not advance internal stream.
impl<'a, F: PRP, T: AsRef<[u8]>, OS> Absorb<External<&'a NBytes<T>>> for Context<OS, F> {
    fn absorb(&mut self, bytes: External<&'a NBytes<T>>) -> Result<&mut Self> {
        self.spongos.absorb(bytes);
        Ok(self)
    }
}

/// Absorbs a 32 byte Ed25519 Public Key into [Spongos](`crate::core::spongos::Spongos`) state but
/// does not advance internal stream.
impl<'a, F: PRP, OS> Absorb<External<&'a ed25519::PublicKey>> for Context<OS, F> {
    fn absorb(&mut self, public_key: External<&'a ed25519::PublicKey>) -> Result<&mut Self> {
        self.spongos.absorb(public_key);
        Ok(self)
    }
}

/// Absorbs a 32 byte X25519 Public Key into [Spongos](`crate::core::spongos::Spongos`) state but
/// does not advance internal stream.
impl<'a, F: PRP, OS> Absorb<External<&'a x25519::PublicKey>> for Context<OS, F> {
    fn absorb(&mut self, public_key: External<&'a x25519::PublicKey>) -> Result<&mut Self> {
        self.spongos.absorb(public_key);
        Ok(self)
    }
}
