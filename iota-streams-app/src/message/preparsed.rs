use anyhow::Result;

use super::*;
use iota_streams_protobuf3::{
    command::unwrap,
    types::Uint8
};
use iota_streams_core::sponge::prp::PRP;

/// Message context preparsed for unwrapping.
pub struct PreparsedMessage<'a, F, Link> {
    pub header: HDF<Link>,
    pub(crate) ctx: unwrap::Context<F, &'a [u8]>,
}

impl<'a, F, Link> PreparsedMessage<'a, F, Link>
{
    pub fn check_content_type(&self, content_type: &Uint8) -> bool {
        self.header.content_type.0 == content_type.0
    }

    pub fn content_type(&self) -> String {
        //(self.header.content_type.0).to_string()
        String::new()
    }

    pub fn unwrap<Store, Content>(
        mut self,
        store: &Store,
        content: Content,
    ) -> Result<UnwrappedMessage<F, Link, Content>>
    where
        Content: ContentUnwrap<F, Store>,
        F: PRP,
    {
        let mut pcf = pcf::PCF::default_with_ctx(content);
        pcf.unwrap(&store, &mut self.ctx)?;
        // Discard what's left of `self.ctx.stream`
        Ok(UnwrappedMessage {
            link: self.header.link,
            pcf: pcf,
            spongos: self.ctx.spongos,
        })
    }
}

impl<'a, F, Link> Clone for PreparsedMessage<'a, F, Link>
where
    F: Clone,
    Link: Clone,
{
    fn clone(&self) -> Self {
        Self {
            header: self.header.clone(),
            ctx: self.ctx.clone(),
        }
    }
}
