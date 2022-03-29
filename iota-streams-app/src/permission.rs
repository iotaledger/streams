use crate::{
    id::Identifier,
    message::*,
};

use iota_streams_core::{
    async_trait,
    err,
    sponge::prp::PRP,
    Errors,
    prelude::{
        Vec,
        Box,
    },
    Result,
};

use iota_streams_ddml::{
    command::*,
    io,
    types::*,
};

use core::convert::TryInto;

#[derive(Clone, Copy, Hash, PartialEq, Eq, Debug)]
pub enum PermissionDuration {
    Perpetual,
    Unix(u64),
    NumBranchMsgs(u32),
    NumPublishedmsgs(u32)
}

impl PermissionDuration {
    pub fn to_bytes(&self) -> Vec<u8> {
        match self {
            // TODO impl real durations
            PermissionDuration::Perpetual => vec![0],
            PermissionDuration::Unix(_) => vec![1],
            PermissionDuration::NumBranchMsgs(_) => vec![2],
            PermissionDuration::NumPublishedmsgs(_) => vec![3],
        }
    }
}

#[async_trait(?Send)]
impl<F: PRP> ContentSizeof<F> for PermissionDuration {
    async fn sizeof<'c>(&self, ctx: &'c mut sizeof::Context<F>) -> Result<&'c mut sizeof::Context<F>> {
        match self {
            _ => {
                // TODO always perpetual
                let oneof = Uint8(0);
                ctx.skip(oneof)?;
                Ok(ctx)
            }
        }
    }
}

#[async_trait(?Send)]
impl<F: PRP, Store> ContentWrap<F, Store> for PermissionDuration {
    async fn wrap<'c, OS: io::OStream>(
        &self,
        _store: &Store,
        ctx: &'c mut wrap::Context<F, OS>,
    ) -> Result<&'c mut wrap::Context<F, OS>> {
        match self {
            _ => {
                // TODO always perpetual
                let oneof = Uint8(0);
                Ok(ctx.mask(oneof)?)
            }
        }
    }
}

#[async_trait(?Send)]
impl<F: PRP, Store> ContentUnwrapNew<F, Store> for PermissionDuration {
    async fn unwrap_new<'c, IS: io::IStream>(
        _store: &Store,
        ctx: &'c mut unwrap::Context<F, IS>,
    ) -> Result<(Self, &'c mut unwrap::Context<F, IS>)> {
        let mut oneof = Uint8(0);
        ctx.mask(&mut oneof)?;
        match oneof.0 {
            _ => {
                Ok((PermissionDuration::Perpetual, ctx))
            }
        }
    }
}

#[derive(Clone, Copy, Hash, PartialEq, Eq, Debug)]
pub enum Permission {
    Read(Identifier),
    ReadWrite(Identifier, PermissionDuration),
    BranchAdmin(Identifier),

}

impl Permission {
    pub fn identifier(&self) -> &Identifier {
        match self {
            Permission::Read(id) => id,
            Permission::ReadWrite(id, _) => id,
            Permission::BranchAdmin(id) => id,
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        match self {
            Permission::Read(_) => vec![0],
            Permission::ReadWrite(_, d) => {
                let mut v = vec![1];
                v.append(&mut d.to_bytes());
                v
            },
            Permission::BranchAdmin(_) => vec![2],
        }
    }
}

impl Default for Permission {
    fn default() -> Self {
        Permission::Read(Identifier::default())
    }
}

#[async_trait(?Send)]
impl<F: PRP> ContentSizeof<F> for Permission {
    async fn sizeof<'c>(&self, ctx: &'c mut sizeof::Context<F>) -> Result<&'c mut sizeof::Context<F>> {
        match self {
            Permission::Read(id) => {
                let oneof = Uint8(0);
                ctx.mask(oneof)?;
                Ok(id.sizeof(ctx).await?)
            }
            Permission::ReadWrite(id, duration) => {
                let oneof = Uint8(1);
                ctx.mask(oneof)?;
                duration.sizeof(ctx).await?;
                Ok(id.sizeof(ctx).await?)
            }
            Permission::BranchAdmin(id) => {
                let oneof = Uint8(2);
                ctx.mask(oneof)?;
                Ok(id.sizeof(ctx).await?)
            }
        }
    }
}

#[async_trait(?Send)]
impl<F: PRP, Store> ContentWrap<F, Store> for Permission {
    async fn wrap<'c, OS: io::OStream>(
        &self,
        _store: &Store,
        ctx: &'c mut wrap::Context<F, OS>,
    ) -> Result<&'c mut wrap::Context<F, OS>> {
        match self {
            Permission::Read(id) => {
                let oneof = Uint8(0);
                ctx.mask(oneof)?;
                Ok(id.wrap(_store, ctx).await?)
            }
            Permission::ReadWrite(id, duration) => {
                let oneof = Uint8(1);
                ctx.mask(oneof)?;
                id.wrap(_store, ctx).await?;
                Ok(duration.wrap(_store, ctx).await?)
            }
            Permission::BranchAdmin(id) => {
                let oneof = Uint8(2);
                ctx.mask(oneof)?;
                Ok(id.wrap(_store, ctx).await?)
            }
        }
    }
}

#[async_trait(?Send)]
impl<F: PRP, Store> ContentUnwrap<F, Store> for Permission {
    async fn unwrap<'c, IS: io::IStream>(
        &mut self,
        _store: &Store,
        ctx: &'c mut unwrap::Context<F, IS>,
    ) -> Result<&'c mut unwrap::Context<F, IS>> {
        let (id, ctx) = Self::unwrap_new(_store, ctx).await?;
        *self = id;
        Ok(ctx)
    }
}

#[async_trait(?Send)]
impl<F: PRP, Store> ContentUnwrapNew<F, Store> for Permission {
    async fn unwrap_new<'c, IS: io::IStream>(
        _store: &Store,
        ctx: &'c mut unwrap::Context<F, IS>,
    ) -> Result<(Self, &'c mut unwrap::Context<F, IS>)> {
        let mut oneof = Uint8(0);
        ctx.mask(&mut oneof)?;
        let id = Identifier::unwrap_new(_store, ctx).await?;
        match oneof.0 {
            0 => {
                let p = Permission::Read(id.0);
                Ok((p, id.1))
            }
            1 => {
                let duration = PermissionDuration::unwrap_new(_store, id.1).await?;
                let p = Permission::ReadWrite(id.0, PermissionDuration::Perpetual);
                Ok((p, duration.1))
            }
            2 => {
                let p = Permission::BranchAdmin(id.0);
                Ok((p, id.1))
            }
            _ => {
                err(Errors::BadOneof)
            },
        }
    }
}

impl core::convert::TryFrom<Vec<u8>> for Permission {
    type Error = Errors;
    fn try_from(bytes: Vec<u8>) -> Result<Self, Self::Error> {
        match bytes[0] {
            // Read
            0 => {
                let id = bytes[1..bytes.len()].to_vec().try_into();
                Ok( Self::Read( id? ) )
            },
            // Write
            1 => {
                let duration = PermissionDuration::Perpetual;
                Ok(Self::ReadWrite(bytes[1..bytes.len()].to_vec().try_into()?, duration))
            },
            // Admin
            2 =>{
                Ok(Self::BranchAdmin(bytes[1..bytes.len()].to_vec().try_into()?))
            },
            _ => Err(Errors::BadOneof),
        }
    }
}

impl core::fmt::Display for Permission {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match *self {
            Permission::Read(id) => write!(f, "Read<{}>", id),
            Permission::ReadWrite(id, duration) => write!(f, "ReadWrite<{}, {:?}>", id, duration),
            Permission::BranchAdmin(id) => write!(f, "BranchAdmin<{}>", id),
        }
    }
}