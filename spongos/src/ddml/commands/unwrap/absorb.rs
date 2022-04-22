// Rust
use alloc::vec::Vec;

// 3rd-party
use anyhow::{
    bail,
    Result,
};
use generic_array::ArrayLength;

// IOTA
use crypto::{
    keys::x25519,
    signatures::ed25519,
};

// Local
use crate::{
    core::prp::PRP,
    ddml::{
        commands::{
            unwrap::{
                Context,
                Unwrap,
            },
            Absorb,
        },
        io,
        types::{
            Bytes,
            NBytes,
            Size,
            Uint16,
            Uint32,
            Uint64,
            Uint8,
        },
    },
    error::Error::PublicKeyGenerationFailure,
};

struct AbsorbContext<'a, F: PRP, IS: io::IStream> {
    ctx: &'a mut Context<F, IS>,
}

impl<'a, F: PRP, IS: io::IStream> AbsorbContext<'a, F, IS> {
    fn new(ctx: &'a mut Context<F, IS>) -> Self {
        Self { ctx }
    }
}

impl<F: PRP, IS: io::IStream> Unwrap for AbsorbContext<'_, F, IS> {
    fn unwrapn<T>(&mut self, mut bytes: T) -> Result<&mut Self> where T: AsMut<[u8]> {
        let bytes = bytes.as_mut();
        let slice = self.ctx.stream.try_advance(bytes.len())?;
        bytes.copy_from_slice(slice);
        self.ctx.spongos.absorb(bytes);
        Ok(self)
    }
}

impl<F: PRP, IS: io::IStream> Absorb<&mut Uint8> for Context<F, IS> {
    fn absorb(&mut self, u: &mut Uint8) -> Result<&mut Self> {
        AbsorbContext::new(self).unwrap_u8(u)?;
        Ok(self)
    }
}

impl<F: PRP, IS: io::IStream> Absorb<&mut Uint16> for Context<F, IS> {
    fn absorb(&mut self, u: &mut Uint16) -> Result<&mut Self> {
        AbsorbContext::new(self).unwrap_u16(u)?;
        Ok(self)
    }
}

impl<F: PRP, IS: io::IStream> Absorb<&mut Uint32> for Context<F, IS> {
    fn absorb(&mut self, u: &mut Uint32) -> Result<&mut Self> {
        AbsorbContext::new(self).unwrap_u32(u)?;
        Ok(self)
    }
}

impl<F: PRP, IS: io::IStream> Absorb<&mut Uint64> for Context<F, IS> {
    fn absorb(&mut self, u: &mut Uint64) -> Result<&mut Self> {
        AbsorbContext::new(self).unwrap_u64(u)?;
        Ok(self)
    }
}

impl<F: PRP, IS: io::IStream> Absorb<&mut Size> for Context<F, IS> {
    fn absorb(&mut self, size: &mut Size) -> Result<&mut Self> {
        AbsorbContext::new(self).unwrap_size(size)?;
        Ok(self)
    }
}

impl<'a, F: PRP, T: AsMut<[u8]>, IS: io::IStream> Absorb<&'a mut NBytes<T>> for Context<F, IS> {
    fn absorb(&mut self, nbytes: &'a mut NBytes<T>) -> Result<&mut Self> {
        AbsorbContext::new(self).unwrapn(nbytes)?;
        Ok(self)
    }
}

impl<'a, F: PRP, IS: io::IStream> Absorb<&'a mut Bytes<Vec<u8>>> for Context<F, IS> {
    fn absorb(&mut self, bytes: &'a mut Bytes<Vec<u8>>) -> Result<&mut Self> {
        self.absorb(&mut Bytes::new(bytes.inner_mut()))
    }
}

impl<'a, F: PRP, IS: io::IStream> Absorb<&'a mut Bytes<&mut Vec<u8>>> for Context<F, IS> {
    fn absorb(&mut self, bytes: &'a mut Bytes<&mut Vec<u8>>) -> Result<&mut Self> {
        let mut size = Size::default();
        self.absorb(&mut size)?;
        bytes.resize(size.inner());
        AbsorbContext::new(self).unwrapn(bytes)?;
        Ok(self)
    }
}

impl<'a, F: PRP, IS: io::IStream> Absorb<&'a mut ed25519::PublicKey> for Context<F, IS> {
    fn absorb(&mut self, public_key: &'a mut ed25519::PublicKey) -> Result<&mut Self> {
        let mut bytes = [0_u8; ed25519::PUBLIC_KEY_LENGTH];
        AbsorbContext::new(self).unwrapn(&mut bytes)?;
        match ed25519::PublicKey::try_from_bytes(bytes) {
            Ok(pk) => {
                *public_key = pk;
                Ok(self)
            }
            Err(_) => bail!(PublicKeyGenerationFailure),
        }
    }
}

impl<'a, F: PRP, IS: io::IStream> Absorb<&'a mut x25519::PublicKey> for Context<F, IS> {
    fn absorb(&mut self, public_key: &'a mut x25519::PublicKey) -> Result<&mut Self> {
        let mut bytes = [0_u8; x25519::PUBLIC_KEY_LENGTH];
        AbsorbContext::new(self).unwrapn(&mut bytes)?;
        *public_key = x25519::PublicKey::from(bytes);
        Ok(self)
    }
}

// TODO: REMOVE
// impl<'a, F: PRP, T: 'a + AbsorbFallback<F>, IS: io::IStream> Absorb<&'a mut Fallback<T>> for Context<F, IS> {
//     fn absorb(&mut self, val: &'a mut Fallback<T>) -> Result<&mut Self> {
//         (val.0).unwrap_absorb(self)?;
//         Ok(self)
//     }
// }
