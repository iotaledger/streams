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
    types::*,
};

/// Message context prepared for wrapping.
struct PreparedMessage<F, Link: Default, Content> {
    header: HDF<Link>,
    content: PCF<Content>,
    _phantom: core::marker::PhantomData<F>,
}

impl<F, Link: Default, Content> PreparedMessage<F, Link, Content> {
    fn new(header: HDF<Link>, content: Content) -> Self {
        let content = pcf::PCF::new_final_frame()
            .with_payload_frame_num(1)
            .unwrap()
            .with_content(content);

        Self {
            header,
            content,
            _phantom: core::marker::PhantomData,
        }
    }
}

impl<'a, F, Link, Content> PreparedMessage<F, Link, Content>
where
    F: PRP,
    Link: HasLink + AbsorbExternalFallback<F> + Clone + Default,
    Link::Rel: Eq + SkipFallback<F>,
{
    async fn wrap<Store>(&self, store: &Store) -> Result<WrappedMessage<F, Link>>
    where
        HDF<Link>: ContentWrap<F, Store>,
        Content: ContentWrap<F, Store>,
    {
        let buf_size = {
            let mut ctx = sizeof::Context::<F>::new();
            self.header.sizeof(&mut ctx).await?;
            self.content.sizeof(&mut ctx).await?;
            ctx.size()
        };

        let mut buf = vec![0; buf_size];

        let spongos = {
            let mut ctx = wrap::Context::new(&mut buf[..]);
            self.header.wrap(store, &mut ctx).await?;
            self.content.wrap(store, &mut ctx).await?;
            assert!(
                ctx.stream().is_empty(), "Missmatch between buffer size expected by SizeOf ({buf_size}) and actual size of Wrap {}", ctx.stream().len());
            ctx.spongos
        };

        Ok(WrappedMessage {
            wrapped: WrapState {
                link: self.header.link.clone(),
                spongos,
            },
            message: BinaryMessage {
                link: self.header.link.clone(),
                prev_link: Link::default(),
                body: buf.into(),
            },
        })
    }
}
