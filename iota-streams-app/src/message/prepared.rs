use anyhow::{
    ensure,
    Result,
};
use core::cell::Ref;

use super::*;
use iota_streams_core::sponge::prp::PRP;
use iota_streams_ddml::types::*;

/// Message context prepared for wrapping.
pub struct PreparedMessage<'a, F, Link, Store: 'a, Content> {
    store: Ref<'a, Store>,
    pub header: Header<Link>,
    pub content: Content,
    _phantom: core::marker::PhantomData<F>,
}

impl<'a, F, Link, Store: 'a, Content> PreparedMessage<'a, F, Link, Store, Content> {
    pub fn new(store: Ref<'a, Store>, header: Header<Link>, content: Content) -> Self {
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
{
    pub fn wrap(&self) -> Result<WrappedMessage<F, Link>>
    where
        Link: HasLink + AbsorbExternalFallback<F> + Clone,
        <Link as HasLink>::Rel: Eq + SkipFallback<F>,
        Store: 'a + LinkStore<F, <Link as HasLink>::Rel>,
        Header<Link>: ContentWrap<F, Store>,
        Content: ContentWrap<F, Store>,
    {
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
            ensure!(ctx.stream.is_empty(), "OStream has not been exhausted.");

            ctx.spongos
        };

        Ok(WrappedMessage {
            spongos: spongos,
            message: BinaryMessage {
                link: self.header.link.clone(),
                body: buf,
                multi_branching: self.header.multi_branching.clone(),
                _phantom: core::marker::PhantomData,
            },
        })
    }
}
