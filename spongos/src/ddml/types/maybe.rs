#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Default)]
pub struct Maybe<T>(T);

impl<T> Maybe<T> {
    pub fn new(t: T) -> Self {
        Self(t)
    }

    pub(crate) fn into_inner(self) -> T {
        self.0
    }
}
