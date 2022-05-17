// Rust
use alloc::vec::Vec;

// 3rd-party
use anyhow::Result;

// IOTA
use crypto::{
    keys::x25519,
    signatures::ed25519,
};

// Local
use crate::{
    core::{
        prp::PRP,
        spongos::Spongos,
    },
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
            Maybe,
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
    ctx: &'a mut Context<IS, F>,
}

impl<'a, F: PRP, IS: io::IStream> MaskContext<'a, F, IS> {
    fn new(ctx: &'a mut Context<IS, F>) -> Self {
        Self { ctx }
    }
}

impl<F: PRP, IS: io::IStream> Unwrap for MaskContext<'_, F, IS> {
    fn unwrapn<T>(&mut self, mut bytes: T) -> Result<&mut Self>
    where
        T: AsMut<[u8]>,
    {
        let y = self.ctx.stream.try_advance(bytes.as_mut().len())?;
        self.ctx.cursor += bytes.as_mut().len();
        self.ctx.spongos.decrypt_mut(y, &mut bytes)?;
        Ok(self)
    }
}

impl<'a, F: PRP, IS: io::IStream> Mask<&'a mut Uint8> for Context<IS, F> {
    fn mask(&mut self, u: &'a mut Uint8) -> Result<&mut Self> {
        MaskContext::new(self).unwrap_u8(u)?;
        Ok(self)
    }
}

impl<'a, F: PRP, IS: io::IStream> Mask<&'a mut Uint16> for Context<IS, F> {
    fn mask(&mut self, u: &'a mut Uint16) -> Result<&mut Self> {
        MaskContext::new(self).unwrap_u16(u)?;
        Ok(self)
    }
}

impl<'a, F: PRP, IS: io::IStream> Mask<&'a mut Uint32> for Context<IS, F> {
    fn mask(&mut self, u: &'a mut Uint32) -> Result<&mut Self> {
        MaskContext::new(self).unwrap_u32(u)?;
        Ok(self)
    }
}

impl<'a, F: PRP, IS: io::IStream> Mask<&'a mut Uint64> for Context<IS, F> {
    fn mask(&mut self, u: &'a mut Uint64) -> Result<&mut Self> {
        MaskContext::new(self).unwrap_u64(u)?;
        Ok(self)
    }
}

impl<'a, F: PRP, IS: io::IStream> Mask<&'a mut Size> for Context<IS, F> {
    fn mask(&mut self, size: &'a mut Size) -> Result<&mut Self> {
        MaskContext::new(self).unwrap_size(size)?;
        Ok(self)
    }
}

impl<F: PRP, T: AsMut<[u8]>, IS: io::IStream> Mask<NBytes<T>> for Context<IS, F> {
    fn mask(&mut self, nbytes: NBytes<T>) -> Result<&mut Self> {
        MaskContext::new(self).unwrapn(nbytes)?;
        Ok(self)
    }
}

impl<'a, F: PRP, IS: io::IStream> Mask<Bytes<&'a mut Vec<u8>>> for Context<IS, F> {
    fn mask(&mut self, mut bytes: Bytes<&'a mut Vec<u8>>) -> Result<&mut Self> {
        let mut size = Size::default();
        self.mask(&mut size)?;
        bytes.resize(size.inner());
        MaskContext::new(self).unwrapn(bytes)?;
        Ok(self)
    }
}

impl<'a, F: PRP, IS: io::IStream> Mask<&'a mut x25519::PublicKey> for Context<IS, F> {
    fn mask(&mut self, public_key: &'a mut x25519::PublicKey) -> Result<&mut Self> {
        let mut bytes = [0u8; x25519::PUBLIC_KEY_LENGTH];
        MaskContext::new(self).unwrapn(&mut bytes)?;
        *public_key = x25519::PublicKey::from(bytes);
        Ok(self)
    }
}

impl<'a, F: PRP, IS: io::IStream> Mask<&'a mut ed25519::PublicKey> for Context<IS, F> {
    fn mask(&mut self, public_key: &'a mut ed25519::PublicKey) -> Result<&mut Self> {
        let mut bytes = [0u8; ed25519::PUBLIC_KEY_LENGTH];
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

impl<IS, F> Mask<&mut Spongos<F>> for Context<IS, F>
where
    F: PRP,
    IS: io::IStream,
{
    fn mask(&mut self, spongos: &mut Spongos<F>) -> Result<&mut Self> {
        MaskContext::new(self)
            .unwrapn(spongos.outer_mut())?
            .unwrapn(spongos.inner_mut())?;
        Ok(self)
    }
}
impl<'a, F, IS, T> Mask<Maybe<&'a mut Option<T>>> for Context<IS, F>
where
    for<'b> Self: Mask<&'b mut T> + Mask<&'b mut Uint8>,
    T: Default,
{
    fn mask(&mut self, maybe: Maybe<&'a mut Option<T>>) -> Result<&mut Self> {
        let mut oneof = Uint8::default();
        let ctx = self.mask(&mut oneof)?;
        if oneof.inner() == 1 {
            let mut t = T::default();
            ctx.mask(&mut t)?;
            *maybe.into_inner() = Some(t);
        };
        Ok(self)
    }
}
