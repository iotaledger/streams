use core::borrow::BorrowMut;

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
            wrap::{
                Context,
                Wrap,
            },
            Absorb,
        },
        io,
        modifiers::External,
        types::{
            Bytes,
            NBytes,
            Size,
            Uint16,
            Uint32,
            Uint64,
            Uint8, Maybe,
        },
    },
};
struct AbsorbContext<'a, F, OS> {
    ctx: &'a mut Context<F, OS>,
}

impl<'a, F, OS> AbsorbContext<'a, F, OS> {
    fn new(ctx: &'a mut Context<F, OS>) -> Self {
        Self { ctx }
    }
}

impl<'a, F: PRP, OS: io::OStream> Wrap for AbsorbContext<'a, F, OS> {
    fn wrapn<T>(&mut self, bytes: T) -> Result<&mut Self>
    where
        T: AsRef<[u8]>,
    {
        let bytes = bytes.as_ref();
        self.ctx.spongos.absorb(bytes);
        self.ctx.stream.try_advance(bytes.len())?.copy_from_slice(bytes);
        Ok(self)
    }
}

impl<F: PRP, OS: io::OStream> Absorb<Uint8> for Context<F, OS> {
    fn absorb(&mut self, u: Uint8) -> Result<&mut Self> {
        AbsorbContext::new(self).wrap_u8(u)?;
        Ok(self)
    }
}

impl<F: PRP, OS: io::OStream> Absorb<Uint16> for Context<F, OS> {
    fn absorb(&mut self, u: Uint16) -> Result<&mut Self> {
        AbsorbContext::new(self).wrap_u16(u)?;
        Ok(self)
    }
}

impl<F: PRP, OS: io::OStream> Absorb<Uint32> for Context<F, OS> {
    fn absorb(&mut self, u: Uint32) -> Result<&mut Self> {
        AbsorbContext::new(self).wrap_u32(u)?;
        Ok(self)
    }
}

impl<F: PRP, OS: io::OStream> Absorb<Uint64> for Context<F, OS> {
    fn absorb(&mut self, u: Uint64) -> Result<&mut Self> {
        AbsorbContext::new(self).wrap_u64(u)?;
        Ok(self)
    }
}

impl<F: PRP, OS: io::OStream> Absorb<Size> for Context<F, OS> {
    fn absorb(&mut self, size: Size) -> Result<&mut Self> {
        AbsorbContext::new(self).wrap_size(size)?;
        Ok(self)
    }
}

impl<'a, F, T, OS> Absorb<NBytes<&'a T>> for Context<F, OS>
where
    F: PRP,
    T: AsRef<[u8]>,
    OS: io::OStream,
{
    fn absorb(&mut self, nbytes: NBytes<&'a T>) -> Result<&mut Self> {
        AbsorbContext::new(self).wrapn(nbytes)?;
        Ok(self)
    }
}

impl<'a, F: PRP, T, OS: io::OStream> Absorb<&'a NBytes<T>> for Context<F, OS>
where
    Self: Absorb<NBytes<&'a T>>,
{
    fn absorb(&mut self, nbytes: &'a NBytes<T>) -> Result<&mut Self> {
        self.absorb(NBytes::new(nbytes.inner()))
    }
}

impl<'a, F: PRP, OS: io::OStream, T> Absorb<Bytes<&'a T>> for Context<F, OS>
where
    T: AsRef<[u8]>,
{
    fn absorb(&mut self, bytes: Bytes<&'a T>) -> Result<&mut Self> {
        self.absorb(Size::new(bytes.len()))?;
        AbsorbContext::new(self).wrapn(bytes)?;
        Ok(self)
    }
}

impl<'a, F: PRP, OS: io::OStream, T> Absorb<&'a Bytes<T>> for Context<F, OS>
where
    Self: Absorb<Bytes<&'a T>>,
{
    fn absorb(&mut self, bytes: &'a Bytes<T>) -> Result<&mut Self> {
        self.absorb(Bytes::new(bytes.inner()))
    }
}

impl<'a, F: PRP, OS: io::OStream> Absorb<&'a ed25519::PublicKey> for Context<F, OS> {
    fn absorb(&mut self, public_key: &'a ed25519::PublicKey) -> Result<&mut Self> {
        AbsorbContext::new(self).wrapn(public_key)?;
        Ok(self)
    }
}

impl<'a, F: PRP, OS: io::OStream> Absorb<&'a x25519::PublicKey> for Context<F, OS> {
    fn absorb(&mut self, public_key: &'a x25519::PublicKey) -> Result<&mut Self> {
        AbsorbContext::new(self).wrapn(public_key)?;
        Ok(self)
    }
}

impl<F, OS, T> Absorb<Maybe<Option<T>>> for Context<F, OS>
where
    Self: Absorb<T> + Absorb<Uint8>,
{
    fn absorb(&mut self, maybe: Maybe<Option<T>>) -> Result<&mut Self> {
        match maybe.into_inner() {
            Some(t) => self.absorb(Uint8::new(1))?.absorb(t)?,
            None => self.absorb(Uint8::new(0))?,
        };
        Ok(self)
    }
}

// TODO: REMOVE
impl<'a, F, OS> Absorb<&'a ()> for Context<F, OS> {
    fn absorb(&mut self, _: &'a ()) -> Result<&mut Self> {
        Ok(self)
    }
}
