use failure::{ensure, Fallible};
use std::cell::Ref;

use super::*;
use iota_streams_core::{
    sponge::prp::PRP,
    tbits::{word::SpongosTbitWord, Tbits},
};
use iota_streams_protobuf3::types::*;

/// Message context prepared for wrapping.
pub struct PreparedMessage<'a, TW, F, Link, Store: 'a, Content> {
    store: Ref<'a, Store>,
    pub header: Header<TW, Link>,
    pub content: Content,
    _phantom: std::marker::PhantomData<F>,
}

impl<'a, TW, F, Link, Store: 'a, Content> PreparedMessage<'a, TW, F, Link, Store, Content> {
    pub fn new(store: Ref<'a, Store>, header: Header<TW, Link>, content: Content) -> Self {
        Self {
            store,
            header,
            content,
            _phantom: std::marker::PhantomData,
        }
    }
}

impl<'a, TW, F, Link, Store, Content> PreparedMessage<'a, TW, F, Link, Store, Content>
where
    TW: SpongosTbitWord,
    F: PRP<TW> + Default,
{
    pub fn wrap(&self) -> Fallible<WrappedMessage<TW, F, Link>>
    where
        Link: HasLink + AbsorbExternalFallback<TW, F> + Clone,
        <Link as HasLink>::Rel: Eq + SkipFallback<TW, F>,
        Store: 'a + LinkStore<TW, F, <Link as HasLink>::Rel>,
        Header<TW, Link>: ContentWrap<TW, F, Store>,
        Content: ContentWrap<TW, F, Store>,
    {
        let buf_size = {
            let mut ctx = sizeof::Context::<TW, F>::new();
            self.header.sizeof(&mut ctx)?;
            self.content.sizeof(&mut ctx)?;
            ctx.get_size()
        };

        let mut buf = Tbits::<TW>::zero(buf_size);

        let spongos = {
            let mut ctx = wrap::Context::new(buf.slice_mut());
            self.header.wrap(&*self.store, &mut ctx)?;
            self.content.wrap(&*self.store, &mut ctx)?;
            ensure!(ctx.stream.is_empty(), "OStream has not been exhausted.");

            ctx.spongos
        };

        Ok(WrappedMessage {
            spongos: spongos,
            message: TbinaryMessage {
                link: self.header.link.clone(),
                body: buf,
                _phantom: std::marker::PhantomData,
            },
        })
    }
}
