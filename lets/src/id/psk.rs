use core::{
    convert::{
        TryFrom,
        TryInto,
    },
    fmt::{
        LowerHex,
        UpperHex,
    },
};

use anyhow::{
    Error,
    Result,
};

use spongos::{
    ddml::{
        commands::{
            sizeof,
            unwrap,
            wrap,
            Mask,
        },
        io,
        types::NBytes,
    },
    KeccakF1600,
    Spongos,
    PRP,
};

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct Psk([u8; 32]);

impl Psk {
    pub fn new(array: [u8; 32]) -> Self {
        Self(array)
    }

    pub fn from_seed<T>(seed: T) -> Self
    where
        T: AsRef<[u8]>,
    {
        let mut spongos = Spongos::<KeccakF1600>::init();
        spongos.absorb("PSK");
        spongos.sponge(seed)
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub(crate) fn to_bytes(self) -> [u8; 32] {
        self.0
    }

    pub fn to_pskid(self) -> PskId {
        let mut spongos = Spongos::<KeccakF1600>::init();
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

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default, Debug)]
pub struct PskId([u8; 16]);

impl PskId {
    pub fn new(array: [u8; 16]) -> Self {
        Self(array)
    }

    pub fn from_seed<T>(seed: T) -> Self
    where
        T: AsRef<[u8]>,
    {
        Psk::from_seed::<T>(seed).to_pskid()
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

impl LowerHex for PskId {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", hex::encode(self))
    }
}

impl UpperHex for PskId {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", hex::encode_upper(self))
    }
}

impl Mask<&PskId> for sizeof::Context {
    fn mask(&mut self, pskid: &PskId) -> Result<&mut Self> {
        self.mask(NBytes::new(pskid))
    }
}

impl<OS, F> Mask<&PskId> for wrap::Context<OS, F>
where
    F: PRP,
    OS: io::OStream,
{
    fn mask(&mut self, pskid: &PskId) -> Result<&mut Self> {
        self.mask(NBytes::new(pskid))
    }
}

impl<IS, F> Mask<&mut PskId> for unwrap::Context<IS, F>
where
    F: PRP,
    IS: io::IStream,
{
    fn mask(&mut self, pskid: &mut PskId) -> Result<&mut Self> {
        self.mask(NBytes::new(pskid))
    }
}

impl Mask<&Psk> for sizeof::Context {
    fn mask(&mut self, psk: &Psk) -> Result<&mut Self> {
        self.mask(NBytes::new(psk))
    }
}

impl<OS, F> Mask<&Psk> for wrap::Context<OS, F>
where
    F: PRP,
    OS: io::OStream,
{
    fn mask(&mut self, psk: &Psk) -> Result<&mut Self> {
        self.mask(NBytes::new(psk))
    }
}

impl<IS, F> Mask<&mut Psk> for unwrap::Context<IS, F>
where
    F: PRP,
    IS: io::IStream,
{
    fn mask(&mut self, psk: &mut Psk) -> Result<&mut Self> {
        self.mask(NBytes::new(psk))
    }
}
