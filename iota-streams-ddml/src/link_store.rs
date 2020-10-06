use anyhow::{
    anyhow,
    Result,
};
use core::hash;

use iota_streams_core::{
    prelude::{
        HashMap,
        Vec,
    },
    sponge::{
        prp::PRP,
        spongos::Spongos,
    },
};

/// The `link` type is generic and transport-specific. Links can be address+tag pair
/// when messages are published in the Tangle. Or links can be a URL when HTTP is used.
/// Or links can be a message sequence number in a stream/socket.
pub trait LinkStore<F, Link> {
    /// Additional data associated with the current message link/spongos state.
    /// This type is implementation specific, meaning different configurations
    /// of a Streams Application can use different Info types.
    type Info;

    /// Lookup link in the store and return spongos state and associated info.
    fn lookup(&self, _link: &Link) -> Result<(Spongos<F>, Self::Info)> {
        Err(anyhow!("Link not found."))
    }

    /// Put link into the store together with spongos state and associated info.
    ///
    /// Implementations should handle the case where link is already in the store,
    /// but spongos state is different. Such situation can indicate an attack,
    /// integrity violation (how exactly?), or internal error.
    ///
    /// Overwriting the spongos state means "forgetting the old and accepting the new".
    ///
    /// Not updating the spongos state means immutability -- "the first one makes the history".
    fn update(&mut self, link: &Link, spongos: Spongos<F>, info: Self::Info) -> Result<()>;

    /// Remove link and associated info from the store.
    fn erase(&mut self, _link: &Link) {}
}

/// Empty "dummy" link store that stores no links.
#[derive(Copy, Clone, Debug)]
pub struct EmptyLinkStore<F, Link, Info>(core::marker::PhantomData<(F, Link, Info)>);

impl<F, Link, Info> Default for EmptyLinkStore<F, Link, Info> {
    fn default() -> Self {
        Self(core::marker::PhantomData)
    }
}

impl<F, Link, Info> LinkStore<F, Link> for EmptyLinkStore<F, Link, Info> {
    type Info = Info;
    fn update(&mut self, _link: &Link, _spongos: Spongos<F>, _info: Self::Info) -> Result<()> {
        Ok(())
    }
}

/// Link store that contains a single link.
/// This link store can be used in Streams Applications supporting a list-like "thread"
/// of messages without access to the history as the link to the last message is stored.
#[derive(Clone, Debug, Default)]
pub struct SingleLinkStore<F, Link, Info> {
    /// The link to the last message in the thread.
    link: Link,

    /// Inner spongos state is stored to save up space.
    spongos: Vec<u8>,

    /// Associated info.
    info: Info,

    _phantom: core::marker::PhantomData<F>,
}

impl<F: PRP, Link, Info> LinkStore<F, Link> for SingleLinkStore<F, Link, Info>
where
    Link: Clone + Eq,
    Info: Clone,
{
    type Info = Info;
    fn lookup(&self, link: &Link) -> Result<(Spongos<F>, Self::Info)> {
        if self.link == *link {
            Ok((Spongos::<F>::from_inner(self.spongos.clone()), self.info.clone()))
        } else {
            Err(anyhow!("Link not found."))
        }
    }
    fn update(&mut self, link: &Link, spongos: Spongos<F>, info: Self::Info) -> Result<()> {
        let inner = spongos.to_inner();
        self.link = link.clone();
        self.spongos = inner;
        self.info = info;
        Ok(())
    }
    fn erase(&mut self, _link: &Link) {
        // Can't really erase link.
    }
}

pub struct DefaultLinkStore<F, Link, Info> {
    map: HashMap<Link, (Vec<u8>, Info)>,
    _phantom: core::marker::PhantomData<F>,
}

impl<F: PRP, Link, Info> Default for DefaultLinkStore<F, Link, Info>
where
    Link: Eq + hash::Hash,
{
    fn default() -> Self {
        Self {
            map: HashMap::new(),
            _phantom: core::marker::PhantomData,
        }
    }
}

impl<F: PRP, Link, Info> LinkStore<F, Link> for DefaultLinkStore<F, Link, Info>
where
    Link: Eq + hash::Hash + Clone,
    Info: Clone,
{
    type Info = Info;

    /// Add info for the link.
    fn lookup(&self, link: &Link) -> Result<(Spongos<F>, Info)> {
        if let Some((inner, info)) = self.map.get(link).cloned() {
            Ok((Spongos::from_inner(inner), info))
        } else {
            Err(anyhow!("Link not found"))
        }
    }

    /// Try to retrieve info for the link.
    fn update(&mut self, link: &Link, spongos: Spongos<F>, info: Info) -> Result<()> {
        let inner = spongos.to_inner();
        self.map.insert(link.clone(), (inner, info));
        Ok(())
    }

    /// Remove info for the link.
    fn erase(&mut self, link: &Link) {
        self.map.remove(link);
    }
}
