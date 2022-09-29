use crate::ddml::commands::{wrap::Context, Fork};

/// Copy context for looped [`Context`] encryption operations
impl<'a, F, OS> Fork<'a> for Context<OS, F>
where
    F: Clone,
    OS: 'a,
{
    type Forked = Context<&'a mut OS, F>;
    fn fork(&'a mut self) -> Context<&'a mut OS, F> {
        let fork = self.spongos.fork();
        Context::new_with_spongos(self.stream_mut(), fork)
    }
}
