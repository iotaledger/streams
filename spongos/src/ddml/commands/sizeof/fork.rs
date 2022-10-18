use crate::ddml::commands::{sizeof::Context, Fork};

/// Copy context for looped [`Context`] encryption operations
impl<'a> Fork<'a> for Context {
    type Forked = &'a mut Context;
    fn fork(&'a mut self) -> Self::Forked {
        self
    }
}
