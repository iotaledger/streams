use failure::ensure;

use iota_mam_core::{trits::Trits, spongos::Spongos};
use iota_mam_protobuf3::{io, types::*, sizeof, wrap, unwrap};

use crate::Result;
use super::*;

pub trait ContentWrap {
    fn sizeof2<'a>(&self, ctx: &'a mut sizeof::Context) -> Result<&'a mut sizeof::Context>;
    fn wrap2<'a, OS: io::OStream>(&'a self, ctx: &'a mut wrap::Context<OS>) -> Result<&'a mut wrap::Context<OS>>;
}

pub struct PreparedMessage<'a, Link, Store: 'a, Content> {
    pub store: &'a mut Store,
    pub header: header::Header<Link>,
    pub content: Content,
    wrap_result: Option<(Trits, Spongos)>,
}

impl<'a, Link, Store: 'a, Content> PreparedMessage<'a, Link, Store, Content> {
    pub fn new(store: &'a mut Store, header: header::Header<Link>, content: Content,) -> Self {
        Self {
            store: store,
            header: header,
            content: content,
            wrap_result: None,
        }
    }
}

impl<'a, Link, Store: 'a, Content> PreparedMessage<'a, Link, Store, Content> where
    Link: HasLink + AbsorbExternalFallback,
    <Link as HasLink>::Rel: Eq + SkipFallback,
    Store: LinkStore<<Link as HasLink>::Rel>,
    Content: ContentWrap,
{
    fn do_wrap(&self) -> Result<(Trits, Spongos)> {
        let buf_size = {
            let mut ctx = sizeof::Context::new();
            self.header.sizeof(&mut ctx)?;
            self.content.sizeof2(&mut ctx)?;
            ctx.get_size()
        };

        let mut buf = Trits::zero(buf_size);

        let spongos = {
            let mut ctx = wrap::Context::new(buf.slice_mut());
            self.header.wrap(&mut ctx)?;
            self.content.wrap2(&mut ctx)?;
            ensure!(ctx.stream.is_empty(), "OStream has not been exhausted.");

            ctx.spongos
        };

        Ok((buf, spongos))
    }

    pub fn wrap(&mut self) -> Result<()> {
        if self.wrap_result.is_none() {
            let result = self.do_wrap()?;
            self.wrap_result = Some(result);
        }
        Ok(())
    }

    pub fn commit(self, info: <Store as LinkStore<<Link as HasLink>::Rel>>::Info) -> Result<TrinaryMessage<Link>> {
        self.do_wrap()?;
        if let Some((buf, spongos)) = self.wrap_result {
            self.store.update(self.header.link.rel(), spongos, info)?;
            Ok(TrinaryMessage{ link: self.header.link, body: buf, })
        } else {
            bail!("PreparedMessage internal error: wrap result is None.")
        }
    }
}
/*
*/

pub trait ContentUnwrap {
    fn unwrap2<'a, IS: io::IStream>(&'a mut self, ctx: &'a mut unwrap::Context<IS>) -> Result<&'a mut unwrap::Context<IS>>;
}

pub mod header;
mod version;

pub use version::*;

