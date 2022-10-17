// Rust

// IOTA

// Streams
use spongos::{
    ddml::{
        commands::{sizeof, unwrap, wrap, Mask},
        io,
        types::Uint8,
    },
    error::{Error as SpongosError, Result as SpongosResult},
    PRP,
};

// Local
use crate::id::identifier::Identifier;

/// Duration with which a `ReadWrite` [`Permissioned`] will be valid for
#[derive(Clone, Copy, Hash, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub enum PermissionDuration {
    /// Indefinite `ReadWrite`
    Perpetual,
    /// `ReadWrite` until the internal `Unix` timestamp elapses
    Unix(u64),
    /// `ReadWrite` until the specified number of messages has been parsed from the branch
    NumBranchMsgs(u32),
    /// `ReadWrite` until the specified number of messages has been parsed from the channel
    NumPublishedmsgs(u32),
}

impl Default for PermissionDuration {
    fn default() -> Self {
        Self::Perpetual
    }
}

impl Mask<&PermissionDuration> for sizeof::Context {
    fn mask(&mut self, duration: &PermissionDuration) -> SpongosResult<&mut Self> {
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
    fn mask(&mut self, duration: &PermissionDuration) -> SpongosResult<&mut Self> {
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
    fn mask(&mut self, duration: &mut PermissionDuration) -> SpongosResult<&mut Self> {
        let mut oneof = Uint8::new(0);
        self.mask(&mut oneof)?;
        match oneof.inner() {
            0 => {
                *duration = PermissionDuration::Perpetual;
            }
            1 | 2 | 3 => todo!(),
            o => return Err(SpongosError::InvalidOption("identifier", o)),
        }
        Ok(self)
    }
}

/// Used to assign Read and Write access to branches within a Stream
#[derive(Clone, Copy, Hash, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub enum Permissioned<Identifier> {
    /// Read Access for the assigned branch
    Read(Identifier),
    /// Read and Write Access for the branch. May send packets within the [`PermissionDuration`].
    ReadWrite(Identifier, PermissionDuration),
    /// Read, Write and Administrative privileges. Allows the User to send Keyloads to manage Read
    /// and Write privileges for other members of the Stream
    Admin(Identifier),
}

impl<Identifier> Permissioned<Identifier> {
    /// Returns a reference to the internal `Identifier` of the permission
    pub fn identifier(&self) -> &Identifier {
        match self {
            Permissioned::Read(id) => id,
            Permissioned::ReadWrite(id, _) => id,
            Permissioned::Admin(id) => id,
        }
    }

    /// Returns a mutable reference to the internal `Identifier` of the permission
    pub fn identifier_mut(&mut self) -> &mut Identifier {
        match self {
            Permissioned::Read(id) => id,
            Permissioned::ReadWrite(id, _) => id,
            Permissioned::Admin(id) => id,
        }
    }

    /// Returns a new [`Permissioned`] wrapper for a reference to the inner values of the current
    /// [`Permissioned`].
    pub fn as_ref(&self) -> Permissioned<&Identifier> {
        match self {
            Self::Read(id) => Permissioned::Read(id),
            Self::ReadWrite(id, duration) => Permissioned::ReadWrite(id, *duration),
            Self::Admin(id) => Permissioned::Admin(id),
        }
    }

    /// Returns if the [`Permissioned`] is [`Permissioned::Read`].
    pub fn is_readonly(&self) -> bool {
        matches!(self, Permissioned::Read(..))
    }

    /// Returns if the [`Permissioned`] is [`Permissioned::Admin`].
    pub fn is_admin(&self) -> bool {
        matches!(self, Permissioned::Admin(..))
    }
}

impl From<Permissioned<&Identifier>> for Permissioned<Identifier> {
    fn from(perm: Permissioned<&Identifier>) -> Self {
        match perm {
            Permissioned::Read(id) => Permissioned::Read(id.clone()),
            Permissioned::ReadWrite(id, duration) => Permissioned::ReadWrite(id.clone(), duration),
            Permissioned::Admin(id) => Permissioned::Admin(id.clone()),
        }
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
    fn mask(&mut self, permission: &Permissioned<Identifier>) -> SpongosResult<&mut Self> {
        self.mask(&permission.as_ref())
    }
}

impl<OS, F> Mask<&Permissioned<Identifier>> for wrap::Context<OS, F>
where
    F: PRP,
    OS: io::OStream,
{
    fn mask(&mut self, permission: &Permissioned<Identifier>) -> SpongosResult<&mut Self> {
        self.mask(&permission.as_ref())
    }
}

impl<IS, F> Mask<&mut Permissioned<Identifier>> for unwrap::Context<IS, F>
where
    F: PRP,
    IS: io::IStream,
{
    fn mask(&mut self, permission: &mut Permissioned<Identifier>) -> SpongosResult<&mut Self> {
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
            o => return Err(SpongosError::InvalidOption("permission", o)),
        }
        Ok(self)
    }
}

impl Mask<&Permissioned<&Identifier>> for sizeof::Context {
    fn mask(&mut self, permission: &Permissioned<&Identifier>) -> SpongosResult<&mut Self> {
        match permission {
            Permissioned::Read(identifier) => {
                let oneof = Uint8::new(0);
                self.mask(oneof)?.mask(*identifier)?;
                Ok(self)
            }
            Permissioned::ReadWrite(identifier, duration) => {
                let oneof = Uint8::new(1);
                self.mask(oneof)?.mask(duration)?.mask(*identifier)?;
                Ok(self)
            }
            Permissioned::Admin(identifier) => {
                let oneof = Uint8::new(2);
                self.mask(oneof)?.mask(*identifier)?;
                Ok(self)
            }
        }
    }
}

impl<OS, F> Mask<&Permissioned<&Identifier>> for wrap::Context<OS, F>
where
    F: PRP,
    OS: io::OStream,
{
    fn mask(&mut self, permission: &Permissioned<&Identifier>) -> SpongosResult<&mut Self> {
        match permission {
            Permissioned::Read(identifier) => {
                let oneof = Uint8::new(0);
                self.mask(oneof)?.mask(*identifier)?;
                Ok(self)
            }
            Permissioned::ReadWrite(identifier, duration) => {
                let oneof = Uint8::new(1);
                self.mask(oneof)?.mask(duration)?.mask(*identifier)?;
                Ok(self)
            }
            Permissioned::Admin(identifier) => {
                let oneof = Uint8::new(2);
                self.mask(oneof)?.mask(*identifier)?;
                Ok(self)
            }
        }
    }
}
