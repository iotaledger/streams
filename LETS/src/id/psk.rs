use alloc::vec::Vec;
use core::convert::{
    TryFrom,
    TryInto,
};

use anyhow::{
    Error,
    Result,
};

use spongos::{
    ddml::types::NBytes,
    Spongos,
    PRP,
};

#[derive(Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct Psk([u8; 32]);

impl Psk {
    fn new<F, T>(seed: T) -> Self
    where
        T: AsRef<[u8]>,
        F: PRP + Default,
    {
        let mut spongos = Spongos::<F>::init();
        spongos.absorb("PSK");
        spongos.sponge(seed)
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub(crate) fn to_bytes(self) -> Vec<u8> {
        self.0.to_vec()
    }

    pub fn to_pskid<F>(self) -> PskId
    where
        F: PRP + Default,
    {
        let mut spongos = Spongos::<F>::init();
        spongos.absorb("PSKID");
        spongos.sponge(self)
    }
}

impl AsRef<[u8]> for Psk {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl AsMut<[u8]> for Psk {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.0
    }
}

impl TryFrom<&[u8]> for Psk {
    type Error = Error;

    fn try_from(bytes: &[u8]) -> Result<Self> {
        Ok(Psk(bytes.try_into()?))
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Hash, Default, Debug)]
pub struct PskId([u8; 16]);

impl PskId {
    fn new<F, T>(seed: T) -> Self
    where
        T: AsRef<[u8]>,
        F: PRP + Default,
    {
        Psk::new::<F, T>(seed).to_pskid::<F>()
    }

    pub(crate) fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl AsRef<[u8]> for PskId {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl AsMut<[u8]> for PskId {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.0
    }
}

impl TryFrom<&[u8]> for PskId {
    type Error = Error;

    fn try_from(bytes: &[u8]) -> Result<Self> {
        Ok(PskId(bytes.try_into()?))
    }
}
