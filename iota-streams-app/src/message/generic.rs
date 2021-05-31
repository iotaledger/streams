use core::fmt;
use iota_streams_core::Result;

use super::LinkedMessage;

/// Binary network Message representation.
#[derive(Clone, PartialEq)]
pub struct GenericMessage<AbsLink, Body> {
    /// Link -- message address.
    pub link: AbsLink,

    /// Message body -- header + content.
    pub body: Body,
}

impl<AbsLink, Body> GenericMessage<AbsLink, Body> {
    pub fn new(link: AbsLink, body: Body) -> Self {
        Self { link, body }
    }

    pub fn map<B, F: FnOnce(Body) -> B>(self, f: F) -> GenericMessage<AbsLink, B> {
        GenericMessage {
            link: self.link,
            body: f(self.body),
        }
    }

    pub fn map_err<B, F: FnOnce(Body) -> Result<B>>(self, f: F) -> Result<GenericMessage<AbsLink, B>> {
        let body = f(self.body)?;
        Ok(GenericMessage { link: self.link, body })
    }
}

impl<AbsLink, Body> LinkedMessage<AbsLink> for GenericMessage<AbsLink, Body> {
    fn link(&self) -> &AbsLink {
        &self.link
    }
}

impl<AbsLink, Body> fmt::Debug for GenericMessage<AbsLink, Body>
where
    AbsLink: fmt::Debug,
    Body: fmt::Debug,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "@{:?}[{:?}]", self.link, self.body)
    }
}

impl<AbsLink, Body> fmt::Display for GenericMessage<AbsLink, Body>
where
    AbsLink: fmt::Display,
    Body: fmt::Display,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "@{}[{}]", self.link, self.body)
    }
}
