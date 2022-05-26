// Rust
use alloc::boxed::Box;
use core::convert::TryInto;

// 3rd-party
use anyhow::{anyhow, Result};
use async_trait::async_trait;

// IOTA

// Streams
use lets::{address::Address, id::Identity, message::TransportMessage, transport::Transport};
use lets::message::Topic;

// Local
use crate::api::user::User;

/// Builder instance for a Streams User
pub struct UserBuilder<T> {
    /// Base Identity that will be used to Identifier a Streams User
    id: Option<Identity>,
    topic: Option<Topic>,
    /// Transport Client instance
    transport: Option<T>,
}

impl<T> Default for UserBuilder<T> {
    fn default() -> Self {
        UserBuilder {
            id: None,
            topic: None,
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
            topic: self.topic,
            id: self.id,
        }
    }

    /// Use the default version of the Transport Client
    pub async fn with_default_transport(mut self) -> Result<Self>
    where
        T: for<'a> Transport<'a> + DefaultTransport,
    {
        // Separated as a method instead of defaulting at the build method to avoid requiring the bespoke
        // bound T: DefaultTransport for all transports
        self.transport = Some(T::try_default().await?);
        Ok(self)
    }

    /// Insert a topic to be used in the channel creation
    pub fn with_topic<Top>(mut self, topic: Top) -> Result<Self>
    where
        Top: AsRef<[u8]>,
    {
        let topic = topic.as_ref().try_into()?;
        self.topic = Some(topic);
        Ok(self)
    }

    /// Build a [`User`] instance using the Builder parameters.
    ///
    /// If a [`Transport`] is not provided the builder will use a default client
    /// ([`Client`](streams_app::transport::tangle::client::Client) at <https://chrysalis-nodes.iota.org>
    /// if the `tangle` feature is enabled,
    /// [`BucketTransport`](streams_app::transport::BucketTransport) if not)
    ///
    /// # Errors
    /// This function will error out if the [`UserIdentity`] parameter is missing, as this makes up
    /// the essence of a [`User`] and is required for any use case.
    ///
    /// # Examples
    /// ## User from Ed25519
    /// ```
    /// # use std::cell::RefCell;
    /// # use std::rc::Rc;
    /// # use anyhow::Result;
    /// # use streams::transport::bucket;
    /// use streams::{id::Ed25519, transport::tangle, User};
    ///
    /// # #[tokio::main]
    /// # async fn main() -> Result<()> {
    /// let user_seed = "cryptographically-secure-random-user-seed";
    /// let transport: tangle::Client = tangle::Client::for_node("https://chrysalis-nodes.iota.org").await?;
    /// #
    /// # let transport: Rc<RefCell<bucket::Client>> = Rc::new(RefCell::new(bucket::Client::new()));
    ///
    /// let mut user = User::builder()
    ///     .with_identity(Ed25519::from_seed(user_seed))
    ///     .with_transport(transport)
    ///     .build()?;
    ///
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// ## User from Psk
    /// ```
    /// # use std::cell::RefCell;
    /// # use std::rc::Rc;
    /// # use anyhow::Result;
    /// # use streams::transport::bucket;
    /// use streams::{id::Psk, transport::tangle, User};
    ///
    /// # #[tokio::main]
    /// # async fn main() -> Result<()> {
    /// let transport: tangle::Client = tangle::Client::for_node("https://chrysalis-nodes.iota.org").await?;
    /// #
    /// # let transport: Rc<RefCell<bucket::Client>> = Rc::new(RefCell::new(bucket::Client::new()));
    /// #
    /// let psk_seed = "seed-for-pre-shared-key";
    ///
    /// let mut user = User::builder()
    ///     .with_identity(Psk::from_seed(psk_seed))
    ///     .with_transport(transport)
    ///     .build()?;
    ///
    /// # Ok(())
    /// # }
    /// ```
    pub fn build(self) -> Result<User<T>> {
        let id = self
            .id
            .ok_or_else(|| anyhow!("user Identity not specified, cannot build User without Identity"))?;

        let transport = self
            .transport
            .ok_or_else(|| anyhow!("transport not specified, cannot build User without Transport"))?;

        let topic = self
            .topic
            .unwrap_or_default();

        Ok(User::new(id, topic, transport))
    }

    /// Recover a user instance from the builder parameters.
    ///
    /// # Arguements
    /// * `announcement` - An existing announcement message link from which to recover the state of
    ///   the user
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
    /// instance without a proper [`Identity`]. It will also return an error
    /// if the provided announcement link is not present on the transport layer.
    ///
    /// # Example
    /// ```
    /// # use std::cell::RefCell;
    /// # use std::rc::Rc;
    /// # use anyhow::Result;
    /// # use streams::transport::bucket;
    /// use streams::{id::Ed25519, transport::tangle, User};
    /// #
    /// # #[tokio::main]
    /// # async fn main() -> Result<()> {
    /// # let test_transport = Rc::new(RefCell::new(bucket::Client::new()));
    /// let author_seed = "author_secure_seed";
    /// let transport: tangle::Client = tangle::Client::for_node("https://chrysalis-nodes.iota.org").await?;
    /// #
    /// # let transport = test_transport.clone();
    /// # let mut author = User::builder()
    /// #     .with_identity(Ed25519::from_seed(author_seed))
    /// #     .with_transport(transport.clone())
    /// #     .build()?;
    /// # let announcement_address = author.create_stream(2).await?.address();
    ///
    /// let author = User::builder()
    ///     .with_identity(Ed25519::from_seed(author_seed))
    ///     .with_transport(transport)
    ///     .recover(announcement_address)
    ///     .await?;
    ///
    /// # Ok(())
    /// # }
    /// ```
    pub async fn recover(self, announcement: Address) -> Result<User<T>>
    where
        T: for<'a> Transport<'a, Msg = TransportMessage>,
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
impl<Message, SendResponse> DefaultTransport for lets::transport::tangle::Client<Message, SendResponse> {
    async fn try_default() -> Result<Self> {
        Self::for_node("https://chrysalis-nodes.iota.org").await
    }
}
