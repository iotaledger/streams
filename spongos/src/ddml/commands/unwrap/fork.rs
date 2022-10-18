use crate::ddml::commands::{unwrap::Context, Fork};

/// Copy context for looped [`Context`] decryption operations
impl<'a, F, IS> Fork<'a> for Context<IS, F>
where
    F: Clone,
    IS: 'a,
{
    type Forked = Context<&'a mut IS, F>;
    fn fork(&'a mut self) -> Context<&'a mut IS, F> {
        let fork = self.spongos.fork();
        Context::new_with_spongos(self.stream_mut(), fork)
    }
}
