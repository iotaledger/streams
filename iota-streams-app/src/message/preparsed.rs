use failure::Fallible;
use std::string::ToString;

use super::*;
use iota_streams_core::tbits::{
    word::StringTbitWord,
    TbitSlice,
};
use iota_streams_protobuf3::command::unwrap;

/// Message context preparsed for unwrapping.
pub struct PreparsedMessage<'a, TW, F, Link> {
    pub header: Header<TW, Link>,
    pub(crate) ctx: unwrap::Context<TW, F, TbitSlice<'a, TW>>,
}

impl<'a, TW, F, Link> PreparsedMessage<'a, TW, F, Link>
where
    TW: StringTbitWord,
{
    pub fn check_content_type(&self, content_type: &str) -> bool {
        (self.header.content_type.0).eq_str(content_type)
    }

    pub fn content_type(&self) -> String {
        (self.header.content_type.0).to_string()
    }

    pub fn unwrap<Store, Content>(
        mut self,
        store: &Store,
        mut content: Content,
    ) -> Fallible<UnwrappedMessage<TW, F, Link, Content>>
    where
        Content: ContentUnwrap<TW, F, Store>,
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

impl<'a, TW, F, Link> Clone for PreparsedMessage<'a, TW, F, Link>
where
    TW: Clone,
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
