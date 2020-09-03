use anyhow::{
    ensure,
    Result,
};
//use std::str::FromStr;

use iota_streams_core::{
    sponge::prp::PRP,
};
use iota_streams_ddml::{
    command::*,
    io,
    types::*,
};

use super::*;

pub const FLAG_BRANCHING_MASK: u8 = 1;

#[derive(Clone)]
pub struct HDF<Link> {
    pub encoding: Uint8,
    pub version: Uint8,
    pub content_type: Uint8,
    pub payload_length: Size,
    pub frame_type: Uint8,
    pub payload_frame_count: Size,
    pub link: Link,
    pub seq_num: Size,

}

impl<Link> HDF<Link>
{
    pub fn new_with_fields(link: Link, content_type: Uint8, payload_length: usize, seq_num: usize) -> Self {
        Self {
            encoding: UTF8,
            version: STREAMS_1_VER,
            content_type: content_type,
            payload_length: Size(payload_length),
            frame_type: HDF_ID,
            payload_frame_count: Size(0),
            link: link,
            seq_num: Size(seq_num),

        }
    }

    pub fn new(link: Link) -> Self {
        Self {
            encoding: UTF8,
            version: STREAMS_1_VER,
            content_type: Uint8(0),
            payload_length: Size(0),
            frame_type: HDF_ID,
            payload_frame_count: Size(0),
            link: link,
            seq_num: Size(0)
        }
    }
}

impl<F, Link, Store> ContentWrap<F, Store> for HDF<Link>
    where
        F: PRP,
        Link: AbsorbExternalFallback<F>,
{
    fn sizeof<'c>(&self, ctx: &'c mut sizeof::Context<F>) -> Result<&'c mut sizeof::Context<F>> {
        ctx.absorb(&self.encoding)?
            .absorb(&self.version)?
            .absorb(&self.content_type)?
            .skip(self.payload_length)?
            .absorb(&self.frame_type)?
            .skip(self.payload_frame_count)?
            .absorb(External(Fallback(&self.link)))?
            .skip(self.seq_num)?;
        Ok(ctx)
    }

    fn wrap<'c, OS: io::OStream>(
        &self,
        _store: &Store,
        ctx: &'c mut wrap::Context<F, OS>,
    ) -> Result<&'c mut wrap::Context<F, OS>> {
        ctx.absorb(&self.encoding)?
            .absorb(&self.version)?
            .absorb(&self.content_type)?
            .skip(self.payload_length)?
            .absorb(&self.frame_type)?
            .skip(self.payload_frame_count)?
            .absorb(External(Fallback(&self.link)))?
            .skip(self.seq_num)?;
        Ok(ctx)
    }
}

impl<F, Link, Store> ContentUnwrap<F, Store> for HDF<Link>
    where
        F: PRP,
        Link: AbsorbExternalFallback<F>,
{
    fn unwrap<'c, IS: io::IStream>(
        &mut self,
        _store: &Store,
        ctx: &'c mut unwrap::Context<F, IS>,
    ) -> Result<&'c mut unwrap::Context<F, IS>> {
        ctx.absorb(&mut self.encoding)?
            .absorb(&mut self.version)?
            .absorb(&mut self.content_type)?
            .skip(&mut self.payload_length)?
            .absorb(&mut self.frame_type)?
            .skip(&mut self.payload_frame_count)?
            .absorb(External(Fallback(&self.link)))?
            .skip(&mut self.seq_num)?;

        ensure!(
            self.frame_type == HDF_ID,
            "Message frame type not supported: {}.",
            self.frame_type
        );
        ensure!(
            self.version == STREAMS_1_VER,
            "Message version not supported: {}.",
            self.version
        );
        Ok(ctx)
    }
}
