use anyhow::Result;
// use std::string::ToString;

use super::*;
use iota_streams_core::prelude::String;
use iota_streams_ddml::command::unwrap;

/// Message context preparsed for unwrapping.
pub struct PreparsedMessage<'a, F, Link> {
    pub header: Header<Link>,
    pub(crate) ctx: unwrap::Context<F, &'a [u8]>,
}

impl<'a, F, Link> PreparsedMessage<'a, F, Link> {
    pub fn check_content_type(&self, content_type: &str) -> bool {
        &self.header.content_type.0[..] == content_type.as_bytes()
    }

    pub fn content_type(&self) -> String {
        //(self.header.content_type.0).to_string()
        String::new()
    }

    pub fn unwrap<Store, Content>(
        mut self,
        store: &Store,
        mut content: Content,
    ) -> Result<UnwrappedMessage<F, Link, Content>>
    where
        Content: ContentUnwrap<F, Store>,
    {
        content.unwrap(&store, &mut self.ctx)?;
        // Discard what's left of `self.ctx.stream`
        Ok(UnwrappedMessage {
            link: self.header.link,
            content: content,
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
