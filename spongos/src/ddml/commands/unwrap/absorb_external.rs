use crypto::{keys::x25519, signatures::ed25519};

use crate::{
    core::prp::PRP,
    ddml::{
        commands::{unwrap::Context, Absorb},
        modifiers::External,
        types::{NBytes, Size, Uint16, Uint32, Uint64, Uint8},
    },
    error::Result,
};

/// Reads a single byte encoded `Uint8` from [Spongos](`crate::core::spongos::Spongos`) state but
/// does not advance internal stream.
impl<F: PRP, IS> Absorb<External<Uint8>> for Context<IS, F> {
    fn absorb(&mut self, u: External<Uint8>) -> Result<&mut Self> {
        self.spongos.absorb(u.into_inner().to_bytes());
        Ok(self)
    }
}

/// Reads a two byte encoded `Uint16` from [Spongos](`crate::core::spongos::Spongos`) state but
/// does not advance internal stream.
impl<F: PRP, IS> Absorb<External<Uint16>> for Context<IS, F> {
    fn absorb(&mut self, u: External<Uint16>) -> Result<&mut Self> {
        self.spongos.absorb(u.into_inner().to_bytes());
        Ok(self)
    }
}

/// Reads a four byte encoded `Uint32` from [Spongos](`crate::core::spongos::Spongos`) state but
/// does not advance internal stream.
impl<F: PRP, IS> Absorb<External<Uint32>> for Context<IS, F> {
    fn absorb(&mut self, u: External<Uint32>) -> Result<&mut Self> {
        self.spongos.absorb(u.into_inner().to_bytes());
        Ok(self)
    }
}

/// Reads an eight byte encoded `Uint64` from [Spongos](`crate::core::spongos::Spongos`) state but
/// does not advance internal stream.
impl<F: PRP, IS> Absorb<External<Uint64>> for Context<IS, F> {
    fn absorb(&mut self, u: External<Uint64>) -> Result<&mut Self> {
        self.spongos.absorb(u.into_inner().to_bytes());
        Ok(self)
    }
}

/// Reads an `n` byte encoded [`Size`] from [Spongos](`crate::core::spongos::Spongos`) state but
/// does not advance internal stream.
impl<F: PRP, IS> Absorb<External<Size>> for Context<IS, F> {
    fn absorb(&mut self, size: External<Size>) -> Result<&mut Self> {
        size.into_inner().encode(|byte| {
            self.spongos.absorb(&[byte]);
            Ok(())
        })?;
        Ok(self)
    }
}

/// Reads an `n` byte encoded [`NBytes`] from [Spongos](`crate::core::spongos::Spongos`) state but
/// does not advance internal stream.
impl<'a, F: PRP, T: AsRef<[u8]>, IS> Absorb<External<&'a NBytes<T>>> for Context<IS, F> {
    fn absorb(&mut self, bytes: External<&'a NBytes<T>>) -> Result<&mut Self> {
        self.spongos.absorb(bytes);
        Ok(self)
    }
}

/// Reads a 32 byte Ed25519 Public Key from [Spongos](`crate::core::spongos::Spongos`) state but
/// does not advance internal stream.
impl<'a, F: PRP, IS> Absorb<External<&'a ed25519::PublicKey>> for Context<IS, F> {
    fn absorb(&mut self, public_key: External<&'a ed25519::PublicKey>) -> Result<&mut Self> {
        self.spongos.absorb(public_key);
        Ok(self)
    }
}

/// Absorbs a 32 byte X25519 Public Key from [Spongos](`crate::core::spongos::Spongos`) state but
/// does not advance internal stream.
impl<'a, F: PRP, IS> Absorb<External<&'a x25519::PublicKey>> for Context<IS, F> {
    fn absorb(&mut self, public_key: External<&'a x25519::PublicKey>) -> Result<&mut Self> {
        self.spongos.absorb(public_key);
        Ok(self)
    }
}
