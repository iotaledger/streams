// Rust
use alloc::vec::Vec;

// IOTA

// Streams
use lets::{
    address::Address,
    id::{Identity, Psk, PskId},
    message::TransportMessage,
    transport::Transport,
};

#[cfg(feature = "utangle-client")]
use lets::transport::utangle;

// Local
use crate::{api::user::User, Result};

/// Builder instance for a Streams [`User`].
pub struct UserBuilder<T> {
    /// Base [`Identity`] that will be used to identify a Streams [`User`]
    id: Option<Identity>,
    /// [`Transport`] Client instance.
    transport: T,
    /// Pre Shared Keys.
    psks: Vec<(PskId, Psk)>,
    /// Spongos Storage Type.
    lean: bool,
}

impl Default for UserBuilder<()> {
    fn default() -> Self {
        UserBuilder {
            id: None,
            transport: (),
            psks: Default::default(),
            lean: false,
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
    /// Inject Base [`Identity`] into the [`User`] Builder.
    ///
    /// # Arguments
    /// * `id` - [`Identity`] to be used for base identification of the Streams User
    pub fn with_identity<I>(mut self, id: I) -> Self
    where
        I: Into<Identity>,
    {
        self.id = Some(id.into());
        self
    }

    /// Set the User Builder lean state to true
    pub fn lean(mut self) -> Self {
        self.lean = true;
        self
    }

    /// Inject [`Transport`] Client instance into the User Builder
    ///
    /// # Arguments
    /// * `transport` - Transport Client to be used by the Streams User
    pub fn with_transport<NewTransport>(self, transport: NewTransport) -> UserBuilder<NewTransport>
    where
        NewTransport: for<'a> Transport<'a>,
    {
        UserBuilder {
            transport,
            id: self.id,
            psks: self.psks,
            lean: self.lean,
        }
    }

    /// Inject a new Pre Shared Key and Id into the User Builder
    ///
    /// # Examples
    /// ## Add Multiple Psks
    /// ```
    /// # use anyhow::Result;
    /// use lets::id::Psk;
    /// use streams::{id::Ed25519, transport::utangle, User};
    /// # #[tokio::main]
    /// # async fn main() -> Result<()> {
    /// let psk1 = Psk::from_seed(b"Psk1");
    /// let psk2 = Psk::from_seed(b"Psk2");
    /// let user = User::builder()
    ///     .with_psk(psk1.to_pskid(), psk1)
    ///     .with_psk(psk2.to_pskid(), psk2)
    ///     .build();
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Arguments
    /// * `pskid` - Pre Shared Key Identifier
    /// * `psk` - Pre Shared Key shared outside of Streams scope
    pub fn with_psk(mut self, pskid: PskId, psk: Psk) -> Self {
        self.psks.push((pskid, psk));
        self
    }
}

impl<T> UserBuilder<T> {
    /// Build a [`User`] instance using the Builder parameters.
    ///
    /// If a [`Transport`] is not provided, the builder will use a default client.
    /// (Default [Client](`utangle::Client`) pointed at <https://chrysalis-nodes.iota.org> if the
    /// `tangle` feature is enabled, [`BucketTransport`](lets::transport::bucket::Client) if not)
    ///
    /// # Examples
    /// ## User from Ed25519
    /// ```
    /// # use anyhow::Result;
    /// use streams::{id::Ed25519, transport::utangle, User};
    ///
    /// # #[tokio::main]
    /// # async fn main() -> Result<()> {
    /// let user_seed = "cryptographically-secure-random-user-seed";
    /// let mut user = User::builder()
    ///     .with_identity(Ed25519::from_seed(user_seed))
    ///     .build();
    ///
    /// # Ok(())
    /// # }
    /// ```

    pub fn build<Trans>(self) -> User<Trans>
    where
        T: IntoTransport<Trans>,
        Trans: for<'a> Transport<'a>,
    {
        User::new(self.id, self.psks, self.transport.into(), self.lean)
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
    /// # use streams::transport::bucket;
    /// use streams::{id::Ed25519, transport::utangle, Result, User};
    /// #
    /// # #[tokio::main]
    /// # async fn main() -> Result<()> {
    /// # let test_transport = Rc::new(RefCell::new(bucket::Client::new()));
    /// let author_seed = "author_secure_seed";
    /// let transport: utangle::Client = utangle::Client::new("https://chrysalis-nodes.iota.org");
    /// #
    /// # let transport = test_transport.clone();
    /// # let mut author = User::builder()
    /// #     .with_identity(Ed25519::from_seed(author_seed))
    /// #     .with_transport(transport.clone())
    /// #     .build();
    /// # let announcement_address = author.create_stream("BASE_BRANCH").await?.address();
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
    pub async fn recover<Trans>(self, announcement: Address) -> Result<User<Trans>>
    where
        T: IntoTransport<Trans>,
        Trans: for<'a> Transport<'a, Msg = TransportMessage>,
    {
        let mut user = self.build();
        user.receive_message(announcement).await?;
        user.sync().await?;
        Ok(user)
    }
}

pub trait IntoTransport<T>
where
    T: for<'a> Transport<'a>,
{
    fn into(self) -> T;
}

#[cfg(feature = "utangle-client")]
impl IntoTransport<utangle::Client> for () {
    fn into(self) -> utangle::Client {
        utangle::Client::default()
    }
}

impl<T> IntoTransport<T> for T
where
    T: for<'a> Transport<'a>,
{
    fn into(self) -> T {
        self
    }
}
