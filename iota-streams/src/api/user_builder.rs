// Rust
use alloc::{
    boxed::Box,
    vec::Vec,
};
use core::{
    fmt::Display,
    hash::Hash,
};

// 3rd-party
use anyhow::{
    anyhow,
    Result,
};
use async_trait::async_trait;
use futures::TryFutureExt;

// IOTA

// Streams
use spongos::{
    ddml::commands::{
        unwrap,
        Absorb,
    },
    PRP,
};
use LETS::{
    id::{
        Identifier,
        Identity,
    },
    link::{
        Address,
        Link,
        LinkGenerator,
    },
    message::TransportMessage,
    transport::Transport,
};

// Local
use crate::api::user::User;

/// Builder instance for a Streams User
pub struct UserBuilder<T> {
    /// Base Identity that will be used to Identifier a Streams User
    id: Option<Identity>,
    /// Transport Client instance
    transport: Option<T>,
}

impl<T> Default for UserBuilder<T> {
    fn default() -> Self {
        UserBuilder {
            id: None,
            transport: None,
        }
    }
}

impl UserBuilder<()> {
    /// Create a new User Builder instance
    pub(crate) fn new() -> Self {
        Self::default()
    }
}

impl<T> UserBuilder<T> {
    /// Inject Base Identity into the User Builder
    ///
    /// # Arguments
    /// * `id` - UserIdentity to be used for base identification of the Streams User
    pub fn with_identity<I>(mut self, id: I) -> Self
    where
        I: Into<Identity>,
    {
        self.id = Some(id.into());
        self
    }

    /// Inject Transport Client instance into the User Builder
    ///
    /// # Arguments
    /// * `transport` - Transport Client to be used by the Streams User
    pub fn with_transport<NewTransport>(self, transport: NewTransport) -> UserBuilder<NewTransport>
    where
        NewTransport: for<'a> Transport<'a>,
    {
        UserBuilder {
            transport: Some(transport),
            id: self.id,
        }
    }

    /// Use the default version of the Transport Client
    pub async fn with_default_transport(mut self) -> Result<Self>
    where
        T: for<'a> Transport<'a> + DefaultTransport,
    {
        // Separated as a method instead of defaulting at the build method to avoid requiring the bespoke bound T:
        // DefaultTransport for all transports
        self.transport = Some(T::try_default().await?);
        Ok(self)
    }

    /// Build a [`User`] instance using the Builder parameters.
    ///
    /// If a [`Transport`] is not provided the builder will use a default client
    /// ([`Client`](iota_streams_app::transport::tangle::client::Client) at <https://chrysalis-nodes.iota.org>
    /// if the `tangle` feature is enabled, [`BucketTransport`](iota_streams_app::transport::BucketTransport)
    /// if not)
    ///
    /// # Errors
    /// This function will error out if the [`UserIdentity`] parameter is missing, as this makes up
    /// the essence of a [`User`] and is required for any use case.
    ///
    /// # Examples
    /// ## User from seed
    /// ```
    /// use iota_streams_app_channels::{
    ///     Tangle,
    ///     UserBuilder,
    ///     UserIdentity,
    /// };
    ///
    /// # use std::cell::RefCell;
    /// # use iota_streams_core::{prelude::Rc, Result};
    /// # use iota_streams_app_channels::api::BucketTransport;
    /// #
    /// # #[tokio::main]
    /// # async fn main() -> Result<()> {
    /// let user_seed = "cryptographically-secure-random-user-seed";
    /// let transport = Tangle::new_from_url("https://chrysalis-nodes.iota.org");
    /// #
    /// # let transport = Rc::new(RefCell::new(BucketTransport::new()));
    ///
    /// let mut user = UserBuilder::new()
    ///     .with_identity(UserIdentity::new(user_seed))
    ///     .with_transport(transport)
    ///     .build()?;
    ///
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// ## User from PskId
    /// ```
    /// use iota_streams_app_channels::{
    ///     api::{
    ///         psk_from_seed,
    ///         pskid_from_psk,
    ///     },
    ///     Tangle,
    ///     UserBuilder,
    ///     UserIdentity,
    /// };
    /// # use std::cell::RefCell;
    /// # use iota_streams_core::{prelude::Rc, Result};
    /// # use iota_streams_app_channels::api::BucketTransport;
    /// #
    /// # #[tokio::main]
    /// # async fn main() -> Result<()> {
    /// let transport = Tangle::new_from_url("https://chrysalis-nodes.iota.org");
    /// #
    /// # let transport = Rc::new(RefCell::new(BucketTransport::new()));
    /// #
    /// let psk_seed = "seed-for-pre-shared-key";
    /// let psk = psk_from_seed(psk_seed.as_bytes());
    /// let pskid = pskid_from_psk(&psk);
    ///
    /// let user_identity = UserIdentity::new_from_psk(pskid, psk);
    /// let mut user = UserBuilder::new()
    ///     .with_identity(user_identity)
    ///     .with_transport(transport)
    ///     .build()?;
    ///
    /// # Ok(())
    /// # }
    /// ```Default
    pub fn build(self) -> Result<User<T>> {
        let id = self
            .id
            .ok_or_else(|| anyhow!("user Identity not specified, cannot build User without Identity"))?;

        let transport = self
            .transport
            .ok_or_else(|| anyhow!("transport not specified, cannot build User without Transport"))?;

        Ok(User::new(id, transport))
    }

    /// Recover a user instance from the builder parameters.
    ///
    /// # Arguements
    /// * `announcement` - An existing announcement message link from which to recover the state of the user
    ///
    /// # Caveats
    /// Under the hood, this method recovers the user by rereading all the
    /// messages of the Stream. Besides the obvious caveat of the potential cost
    /// of execution, keep in mind that only the information present as messages
    /// in the stream will be recovered; OOB actions, particularly manually
    /// added or removed subscribers and PSK, will not be recovered and will
    /// need to be reapplied manually.
    ///
    /// # Errors
    /// This function will produce errors if the [`User`] tries to recover their
    /// instance without a proper [`UserIdentity`]. It will also return an error
    /// if the provided announcement link is not present on the transport layer.
    ///
    /// # Example
    /// ```
    /// # use std::cell::RefCell;
    /// # use iota_streams_core::{
    /// #     prelude::Rc,
    /// #     Result,
    /// # };
    /// # use iota_streams_app_channels::api::BucketTransport;
    /// use iota_streams_app_channels::{
    ///     Tangle,
    ///     UserBuilder,
    ///     UserIdentity,
    /// };
    /// #
    /// # #[tokio::main]
    /// # async fn main() -> Result<()> {
    /// # let test_transport = Rc::new(RefCell::new(BucketTransport::new()));
    ///
    /// let author_seed = "author_secure_seed";
    /// let transport = Tangle::new_from_url("https://chrysalis-nodes.iota.org");
    /// #
    /// # let transport = test_transport.clone();
    /// #
    /// # let mut author = UserBuilder::new()
    /// #     .with_identity(UserIdentity::new(author_seed))
    /// #     .with_transport(transport.clone())
    /// #     .build()?;
    /// #
    /// # let announcement_link = author.send_announce().await?;
    ///
    /// let mut author = UserBuilder::new()
    ///     .with_identity(UserIdentity::new(author_seed))
    ///     .with_transport(transport)
    ///     .recover(&announcement_link)
    ///     .await?;
    ///
    /// # Ok(())
    /// # }
    /// ```
    async fn recover(self, announcement: Address) -> Result<User<T>>
    where
        //     A: Link + Display + Clone,
        //     A::Base: Clone,
        //     A::Relative: Clone + Eq + Hash + Default,
        //     F: PRP + Default + Clone,
        //     for<'a, 'b> unwrap::Context<F, &'a [u8]>: Absorb<&'b mut A::Relative>,
        //     // Hack necessary to workaround apparent infinite recursivity in Absorb<&mut Option<T>> for unwrap::Context.
        //     // Investigate!
        //     for<'a, 'b, 'c> &'a mut unwrap::Context<F, &'b [u8]>: Absorb<&'c mut A::Relative>,
        T: for<'a> Transport<'a, Address = &'a Address, Msg = TransportMessage<Vec<u8>>>,
        //     AG: for<'a> LinkGenerator<'a, A::Relative, Data = (&'a A::Base, Identifier, u64)> + Default,
    {
        let mut user = self.build()?;
        user.receive_message(announcement).await?;
        user.sync().await?;
        Ok(user)
    }
}

#[async_trait(?Send)]
pub trait DefaultTransport
where
    Self: Sized,
{
    async fn try_default() -> Result<Self>;
}

#[async_trait(?Send)]
#[cfg(any(feature = "tangle-client", feature = "tangle-client-wasm"))]
impl<Message, SendResponse> DefaultTransport for LETS::transport::tangle::Client<Message, SendResponse> {
    async fn try_default() -> Result<Self> {
        Self::for_node("https://chrysalis-nodes.iota.org").await
    }
}
