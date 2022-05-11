use crate::ddml::commands::{
    wrap::Context,
    Fork,
};

impl<'a, F, OS> Fork<'a> for Context<F, OS>
where
    F: Clone,
    OS: 'a,
{
    type Forked = Context<F, &'a mut OS>;
    fn fork(&'a mut self) -> Context<F, &'a mut OS> {
        let fork = self.spongos.fork();
        Context::new_with_spongos(self.stream_mut(), fork)
    }
}
