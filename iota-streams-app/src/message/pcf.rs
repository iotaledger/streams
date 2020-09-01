use anyhow::Result;
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

pub struct PCF<Content> {
    pub frame_type: Uint8,
    pub payload_frame_num: Size,
    pub content: Content,
}

impl <Content> PCF<Content>
{
    pub fn new(frame_type: Uint8, payload_frame_num: usize, content: Content) -> Self {
        Self {
            frame_type: frame_type,
            payload_frame_num: Size(payload_frame_num),
            content: content,
        }
    }

    pub fn default_with_ctx(content: Content) -> Self {
        Self::new(FINAL_PCF_ID, 1, content)
    }
}

impl<F, Content, Store> ContentWrap<F, Store> for PCF<Content>
    where
        F: PRP,
        Content: ContentWrap<F, Store>,
{
    fn sizeof<'c>(&self, mut ctx: &'c mut sizeof::Context<F>) -> Result<&'c mut sizeof::Context<F>> {
        ctx.absorb(&self.frame_type)?
            .skip(self.payload_frame_num)?;
        self.content.sizeof(&mut ctx)?;
        Ok(ctx)
    }

    fn wrap<'c, OS: io::OStream>(
        &self,
        store: &Store,
        mut ctx: &'c mut wrap::Context<F, OS>,
    ) -> Result<&'c mut wrap::Context<F, OS>> {
        ctx.absorb(&self.frame_type)?
            .skip(self.payload_frame_num)?;
        self.content.wrap(store,&mut ctx)?;
        Ok(ctx)
    }
}

impl<F, Content, Store> ContentUnwrap<F, Store> for PCF<Content>
    where
        F: PRP,
        Content: ContentUnwrap<F, Store>,
{
    fn unwrap<'c, IS: io::IStream>(
        &mut self,
        store: &Store,
        mut ctx: &'c mut unwrap::Context<F, IS>,
    ) -> Result<&'c mut unwrap::Context<F, IS>> {
        ctx.absorb(&mut self.frame_type)?
            .skip(&mut self.payload_frame_num)?;
        self.content.unwrap(&store, &mut ctx)?;
        Ok(ctx)
    }
}
