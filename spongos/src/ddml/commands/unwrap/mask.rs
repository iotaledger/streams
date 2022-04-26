// Rust
use alloc::vec::Vec;

// 3rd-party
use anyhow::Result;
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
            Mask,
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

struct MaskContext<'a, F, IS> {
    ctx: &'a mut Context<F, IS>,
}

impl<'a, F: PRP, IS: io::IStream> MaskContext<'a, F, IS> {
    fn new(ctx: &'a mut Context<F, IS>) -> Self {
        Self { ctx }
    }
}

impl<F: PRP, IS: io::IStream> Unwrap for MaskContext<'_, F, IS> {
    fn unwrapn<T>(&mut self, mut bytes: T) -> Result<&mut Self>
    where
        T: AsMut<[u8]>,
    {
        let y = self.ctx.stream.try_advance(bytes.as_mut().len())?;
        self.ctx.spongos.decrypt_mut(y, bytes)?;
        Ok(self)
    }
}

impl<'a, F: PRP, IS: io::IStream> Mask<&'a mut Uint8> for Context<F, IS> {
    fn mask(&mut self, u: &'a mut Uint8) -> Result<&mut Self> {
        MaskContext::new(self).unwrap_u8(u)?;
        Ok(self)
    }
}

impl<'a, F: PRP, IS: io::IStream> Mask<&'a mut Uint16> for Context<F, IS> {
    fn mask(&mut self, u: &'a mut Uint16) -> Result<&mut Self> {
        MaskContext::new(self).unwrap_u16(u)?;
        Ok(self)
    }
}

impl<'a, F: PRP, IS: io::IStream> Mask<&'a mut Uint32> for Context<F, IS> {
    fn mask(&mut self, u: &'a mut Uint32) -> Result<&mut Self> {
        MaskContext::new(self).unwrap_u32(u)?;
        Ok(self)
    }
}

impl<'a, F: PRP, IS: io::IStream> Mask<&'a mut Uint64> for Context<F, IS> {
    fn mask(&mut self, u: &'a mut Uint64) -> Result<&mut Self> {
        MaskContext::new(self).unwrap_u64(u)?;
        Ok(self)
    }
}

impl<'a, F: PRP, IS: io::IStream> Mask<&'a mut Size> for Context<F, IS> {
    fn mask(&mut self, size: &'a mut Size) -> Result<&mut Self> {
        MaskContext::new(self).unwrap_size(size)?;
        Ok(self)
    }
}

impl<'a, F: PRP, T: AsMut<[u8]>, IS: io::IStream> Mask<NBytes<&'a mut T>> for Context<F, IS> {
    fn mask(&mut self, nbytes: NBytes<&'a mut T>) -> Result<&mut Self> {
        MaskContext::new(self).unwrapn(nbytes)?;
        Ok(self)
    }
}

impl<'a, F: PRP, T, IS: io::IStream> Mask<&'a mut NBytes<T>> for Context<F, IS>
where
    Self: Mask<NBytes<&'a mut T>>,
{
    fn mask(&mut self, nbytes: &'a mut NBytes<T>) -> Result<&mut Self> {
        self.mask(NBytes::new(nbytes.inner_mut()))
    }
}

impl<'a, F: PRP, IS: io::IStream> Mask<&'a mut Bytes<Vec<u8>>> for Context<F, IS> {
    fn mask(&mut self, bytes: &'a mut Bytes<Vec<u8>>) -> Result<&mut Self> {
        self.mask(Bytes::new(bytes.inner_mut()))
    }
}

impl<'a, F: PRP, IS: io::IStream> Mask<Bytes<&'a mut Vec<u8>>> for Context<F, IS> {
    fn mask(&mut self, mut bytes: Bytes<&'a mut Vec<u8>>) -> Result<&mut Self> {
        let mut size = Size::default();
        self.mask(&mut size)?;
        bytes.resize(size.inner());
        MaskContext::new(self).unwrapn(bytes)?;
        Ok(self)
    }
}

impl<'a, F: PRP, IS: io::IStream> Mask<&'a mut x25519::PublicKey> for Context<F, IS> {
    fn mask(&mut self, public_key: &'a mut x25519::PublicKey) -> Result<&mut Self> {
        let mut bytes = [0_u8; x25519::PUBLIC_KEY_LENGTH];
        MaskContext::new(self).unwrapn(&mut bytes)?;
        *public_key = x25519::PublicKey::from(bytes);
        Ok(self)
    }
}

impl<'a, F: PRP, IS: io::IStream> Mask<&'a mut ed25519::PublicKey> for Context<F, IS> {
    fn mask(&mut self, public_key: &'a mut ed25519::PublicKey) -> Result<&mut Self> {
        let mut bytes = [0_u8; ed25519::PUBLIC_KEY_LENGTH];
        MaskContext::new(self).unwrapn(&mut bytes)?;
        match ed25519::PublicKey::try_from_bytes(bytes) {
            Ok(pk) => {
                *public_key = pk;
                Ok(self)
            }
            Err(e) => Err(PublicKeyGenerationFailure.wrap(&e)),
        }
    }
}

impl<'a, F: PRP, IS: io::IStream, T> Mask<&'a mut Option<T>> for Context<F, IS>
where
    for<'b> &'b mut Self: Mask<&'b mut T>,
    T: Default,
{
    fn mask(&mut self, option: &'a mut Option<T>) -> Result<&mut Self> {
        let mut oneof = Uint8::default();
        let mut ctx = self.mask(&mut oneof)?;
        if oneof.inner() == 1 {
            let mut t = T::default();
            // This hacky &mut is necessary to break the recursivity of the trait bound
            (&mut ctx).mask(&mut t)?;
            *option = Some(t);
        };
        Ok(self)
    }
}
