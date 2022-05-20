// Rust

// 3rd-party
use anyhow::{anyhow, Result};

// IOTA

// Streams
use spongos::{
    ddml::{
        commands::{sizeof, unwrap, wrap, Mask},
        io,
        types::Uint8,
    },
    PRP,
};

// Local
use crate::id::{identifier::Identifier, PskId};

#[derive(Clone, Copy, Hash, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub enum PermissionDuration {
    Perpetual,
    Unix(u64),
    NumBranchMsgs(u32),
    NumPublishedmsgs(u32),
}

impl Default for PermissionDuration {
    fn default() -> Self {
        Self::Perpetual
    }
}

impl Mask<&PermissionDuration> for sizeof::Context {
    fn mask(&mut self, duration: &PermissionDuration) -> Result<&mut Self> {
        match duration {
            PermissionDuration::Perpetual => {
                self.mask(Uint8::new(0))?;
                Ok(self)
            }
            _ => todo!(),
        }
    }
}

impl<OS, F> Mask<&PermissionDuration> for wrap::Context<OS, F>
where
    F: PRP,
    OS: io::OStream,
{
    fn mask(&mut self, duration: &PermissionDuration) -> Result<&mut Self> {
        match &duration {
            PermissionDuration::Perpetual => {
                self.mask(Uint8::new(0))?;
                Ok(self)
            }
            _ => todo!(),
        }
    }
}

impl<IS, F> Mask<&mut PermissionDuration> for unwrap::Context<IS, F>
where
    F: PRP,
    IS: io::IStream,
{
    fn mask(&mut self, duration: &mut PermissionDuration) -> Result<&mut Self> {
        let mut oneof = Uint8::new(0);
        self.mask(&mut oneof)?;
        match oneof.inner() {
            0 => {
                *duration = PermissionDuration::Perpetual;
            }
            1 | 2 | 3 => todo!(),
            o => return Err(anyhow!("{} is not a valid identifier option", o)),
        }
        Ok(self)
    }
}

#[derive(Clone, Copy, Hash, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub enum Permissioned<Identifier> {
    Read(Identifier),
    ReadWrite(Identifier, PermissionDuration),
    Admin(Identifier),
}

impl<Identifier> Permissioned<Identifier> {
    pub fn identifier(&self) -> &Identifier {
        match self {
            Permissioned::Read(id) => id,
            Permissioned::ReadWrite(id, _) => id,
            Permissioned::Admin(id) => id,
        }
    }

    pub fn identifier_mut(&mut self) -> &mut Identifier {
        match self {
            Permissioned::Read(id) => id,
            Permissioned::ReadWrite(id, _) => id,
            Permissioned::Admin(id) => id,
        }
    }

    pub fn is_readonly(&self) -> bool {
        matches!(self, Permissioned::Read(..))
    }
}

impl<Identifier> AsRef<Identifier> for Permissioned<Identifier> {
    fn as_ref(&self) -> &Identifier {
        self.identifier()
    }
}

impl<Identifier> AsMut<Identifier> for Permissioned<Identifier> {
    fn as_mut(&mut self) -> &mut Identifier {
        self.identifier_mut()
    }
}

impl<Identifier> Default for Permissioned<Identifier>
where
    Identifier: Default,
{
    fn default() -> Self {
        Permissioned::Read(Identifier::default())
    }
}

impl Mask<&Permissioned<Identifier>> for sizeof::Context {
    fn mask(&mut self, permission: &Permissioned<Identifier>) -> Result<&mut Self> {
        match permission {
            Permissioned::Read(identifier) => {
                let oneof = Uint8::new(0);
                self.mask(oneof)?.mask(identifier)?;
                Ok(self)
            }
            Permissioned::ReadWrite(identifier, duration) => {
                let oneof = Uint8::new(1);
                self.mask(oneof)?.mask(duration)?.mask(identifier)?;
                Ok(self)
            }
            Permissioned::Admin(identifier) => {
                let oneof = Uint8::new(2);
                self.mask(oneof)?.mask(identifier)?;
                Ok(self)
            }
        }
    }
}

impl<OS, F> Mask<&Permissioned<Identifier>> for wrap::Context<OS, F>
where
    F: PRP,
    OS: io::OStream,
{
    fn mask(&mut self, permission: &Permissioned<Identifier>) -> Result<&mut Self> {
        match permission {
            Permissioned::Read(identifier) => {
                let oneof = Uint8::new(0);
                self.mask(oneof)?.mask(identifier)?;
                Ok(self)
            }
            Permissioned::ReadWrite(identifier, duration) => {
                let oneof = Uint8::new(1);
                self.mask(oneof)?.mask(duration)?.mask(identifier)?;
                Ok(self)
            }
            Permissioned::Admin(identifier) => {
                let oneof = Uint8::new(2);
                self.mask(oneof)?.mask(identifier)?;
                Ok(self)
            }
        }
    }
}

impl<IS, F> Mask<&mut Permissioned<Identifier>> for unwrap::Context<IS, F>
where
    F: PRP,
    IS: io::IStream,
{
    fn mask(&mut self, permission: &mut Permissioned<Identifier>) -> Result<&mut Self> {
        let mut oneof = Uint8::new(0);
        self.mask(&mut oneof)?;
        match oneof.inner() {
            0 => {
                let mut identifier = Identifier::default();
                self.mask(&mut identifier)?;
                *permission = Permissioned::Read(identifier);
            }
            1 => {
                let mut identifier = Identifier::default();
                let mut duration = PermissionDuration::default();
                self.mask(&mut duration)?.mask(&mut identifier)?;
                *permission = Permissioned::ReadWrite(identifier, duration);
            }
            2 => {
                let mut identifier = Identifier::default();
                self.mask(&mut identifier)?;
                *permission = Permissioned::Admin(identifier);
            }
            o => return Err(anyhow!("{} is not a valid permission option", o)),
        }
        Ok(self)
    }
}

impl Mask<&Permissioned<PskId>> for sizeof::Context {
    fn mask(&mut self, permission: &Permissioned<PskId>) -> Result<&mut Self> {
        match permission {
            Permissioned::Read(pskid) => {
                let oneof = Uint8::new(0);
                self.mask(oneof)?.mask(pskid)?;
                Ok(self)
            }
            _ => return Err(anyhow!("Psk's can only be used as ReadOnly Permissioned")),
        }
    }
}

impl<OS, F> Mask<&Permissioned<PskId>> for wrap::Context<OS, F>
where
    F: PRP,
    OS: io::OStream,
{
    fn mask(&mut self, permission: &Permissioned<PskId>) -> Result<&mut Self> {
        match permission {
            Permissioned::Read(pskid) => {
                let oneof = Uint8::new(0);
                self.mask(oneof)?.mask(pskid)?;
                Ok(self)
            }
            _ => return Err(anyhow!("Psk's can only be used as ReadOnly Permissioned")),
        }
    }
}

impl<IS, F> Mask<&mut Permissioned<PskId>> for unwrap::Context<IS, F>
where
    F: PRP,
    IS: io::IStream,
{
    fn mask(&mut self, permission: &mut Permissioned<PskId>) -> Result<&mut Self> {
        let mut oneof = Uint8::new(0);
        self.mask(&mut oneof)?;
        match oneof.inner() {
            0 => {
                let mut psk_id = PskId::default();
                self.mask(&mut psk_id)?;
                *permission = Permissioned::Read(psk_id);
            }
            o => return Err(anyhow!("{} is not a valid permission option", o)),
        }
        Ok(self)
    }
}
