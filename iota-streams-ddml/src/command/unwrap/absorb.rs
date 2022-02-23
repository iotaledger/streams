use crypto::{
    keys::x25519,
    signatures::ed25519,
};

use iota_streams_core::{
    err,
    sponge::prp::PRP,
    Errors::PublicKeyGenerationFailure,
    Result,
};

use super::{
    unwrap::Unwrap,
    Context,
};
use crate::{
    command::Absorb,
    io,
    types::{
        AbsorbFallback,
        ArrayLength,
        Bytes,
        Fallback,
        NBytes,
        Size,
        Uint16,
        Uint32,
        Uint64,
        Uint8,
    },
};

struct AbsorbContext<'a, F, IS> {
    ctx: &'a mut Context<F, IS>,
}

impl<'a, F, IS> AbsorbContext<'a, F, IS> {
    fn new(ctx: &'a mut Context<F, IS>) -> Self {
        Self { ctx }
    }
}

impl<F: PRP, IS: io::IStream> Unwrap for AbsorbContext<'_, F, IS> {
    fn unwrapn(&mut self, bytes: &mut [u8]) -> Result<&mut Self> {
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

impl<'a, F: PRP, N: ArrayLength<u8>, IS: io::IStream> Absorb<&'a mut NBytes<N>> for Context<F, IS> {
    fn absorb(&mut self, nbytes: &'a mut NBytes<N>) -> Result<&mut Self> {
        AbsorbContext::new(self).unwrapn(nbytes.as_mut_slice())?;
        Ok(self)
    }
}

impl<'a, F: PRP, IS: io::IStream> Absorb<&'a mut Bytes> for Context<F, IS> {
    fn absorb(&mut self, bytes: &'a mut Bytes) -> Result<&mut Self> {
        let mut size = Size(0);
        self.absorb(&mut size)?;
        (bytes.0).resize(size.0, 0);
        AbsorbContext::new(self).unwrapn(bytes.as_mut_slice())?;
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
            Err(_) => err!(PublicKeyGenerationFailure),
        }
    }
}

impl<'a, F: PRP, IS: io::IStream> Absorb<&'a mut x25519::PublicKey> for Context<F, IS> {
    fn absorb(&mut self, public_key: &'a mut x25519::PublicKey) -> Result<&mut Self> {
        let mut bytes = [0_u8; x25519::PUBLIC_KEY_LENGTH];
        AbsorbContext::new(self).unwrapn(bytes.as_mut_slice())?;
        *public_key = x25519::PublicKey::from(bytes);
        Ok(self)
    }
}

impl<'a, F, T: 'a + AbsorbFallback<F>, IS: io::IStream> Absorb<&'a mut Fallback<T>> for Context<F, IS> {
    fn absorb(&mut self, val: &'a mut Fallback<T>) -> Result<&mut Self> {
        (val.0).unwrap_absorb(self)?;
        Ok(self)
    }
}
