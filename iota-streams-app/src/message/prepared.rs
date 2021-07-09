use core::cell::Ref;
use iota_streams_core::Result;

use super::*;
use iota_streams_core::{
    sponge::prp::PRP,
    try_or,
    Errors::OutputStreamNotFullyConsumed,
};
use iota_streams_ddml::{
    command::{
        sizeof,
        wrap,
    },
    link_store::LinkStore,
    types::*,
};

/// Message context prepared for wrapping.
pub struct PreparedMessage<'a, F, Link, Store: 'a, Content> {
    store: Ref<'a, Store>,
    pub header: HDF<Link>,
    pub content: PCF<Content>,
    _phantom: core::marker::PhantomData<F>,
}

impl<'a, F, Link, Store: 'a, Content> PreparedMessage<'a, F, Link, Store, Content> {
    pub fn new(store: Ref<'a, Store>, header: HDF<Link>, content: Content) -> Self {
        let content = pcf::PCF::new_final_frame()
            .with_payload_frame_num(1)
            .unwrap()
            .with_content(content);

        Self {
            store,
            header,
            content,
            _phantom: core::marker::PhantomData,
        }
    }
}

impl<'a, F, Link, Store, Content> PreparedMessage<'a, F, Link, Store, Content>
where
    F: PRP,
    Link: HasLink + AbsorbExternalFallback<F> + Clone,
    <Link as HasLink>::Rel: Eq + SkipFallback<F>,
    Store: 'a + LinkStore<F, <Link as HasLink>::Rel>,
    HDF<Link>: ContentWrap<F, Store>,
    Content: ContentWrap<F, Store>,
{
    pub fn wrap(&self) -> Result<WrappedMessage<F, Link>> {
        let buf_size = {
            let mut ctx = sizeof::Context::<F>::new();
            self.header.sizeof(&mut ctx)?;
            self.content.sizeof(&mut ctx)?;
            ctx.get_size()
        };

        let mut buf = vec![0; buf_size];

        let spongos = {
            let mut ctx = wrap::Context::new(&mut buf[..]);
            self.header.wrap(&*self.store, &mut ctx)?;
            self.content.wrap(&*self.store, &mut ctx)?;
            try_or!(ctx.stream.is_empty(), OutputStreamNotFullyConsumed(ctx.stream.len()))?;
            ctx.spongos
        };

        Ok(WrappedMessage {
            wrapped: WrapState {
                link: self.header.link.clone(),
                spongos,
            },
            message: BinaryMessage {
                link: self.header.link.clone(),
                body: buf.into(),
            },
        })
    }
}
