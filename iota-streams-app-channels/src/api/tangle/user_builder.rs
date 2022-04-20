use crate::api::{
    tangle::{
        MsgInfo,
        Transport,
        User,
    },
    Address,
    DefaultF,
    Message,
};
use iota_streams_app::id::{
    Identifier,
    UserIdentity,
};
use iota_streams_core::{
    err,
    Errors::{
        UserIdentityMissing,
        UserTransportMissing,
    },
    Result,
};

/// Builder instance for a Streams User
pub struct UserBuilder<Trans: Transport + Clone, F> {
    /// Base Identity that will be used to Identifier a Streams User
    pub id: Option<UserIdentity<F>>,
    /// Alternate Identity that can be used to mask the direct Identity of a Streams User
    pub alias: Option<UserIdentity<F>>,
    /// Transport Client instance
    pub transport: Option<Trans>,
    /// Represents whether the User Instance will automatically sync before each message operation
    pub auto_sync: bool,
}

impl<Trans: Transport + Clone, F> Default for UserBuilder<Trans, F> {
    fn default() -> Self {
        UserBuilder {
            id: None,
            alias: None,
            transport: None,
            auto_sync: true,
        }
    }
}

impl<Trans: Transport> UserBuilder<Trans, DefaultF> {
    /// Create a new User Builder instance
    pub fn new() -> Self {
        Self::default()
    }

    /// Inject Base Identity into the User Builder
    ///
    /// # Arguments
    /// * `id` - UserIdentity to be used for base identification of the Streams User
    pub fn with_identity(mut self, id: UserIdentity<DefaultF>) -> Self {
        self.id = Some(id);
        self
    }

    /// Inject Alternate Identity into the User Builder
    ///
    /// # Arguments
    /// * `alias` - UserIdentity to be used for alternate identification of the Streams User
    pub fn with_alias(mut self, alias: UserIdentity<DefaultF>) -> Self {
        self.alias = Some(alias);
        self
    }

    /// Inject Transport Client instance into the User Builder
    ///
    /// # Arguments
    /// * `transport` - Transport Client to be used by the Streams User
    pub fn with_transport(mut self, transport: Trans) -> Self {
        self.transport = Some(transport);
        self
    }

    /// Set the auto-sync value of the User Builder
    ///
    /// # Arguments
    /// * `auto_sync` - True if the User should automatically perform synchronisation before operations
    pub fn with_auto_sync(mut self, auto_sync: bool) -> Self {
        self.auto_sync = auto_sync;
        self
    }

    /// Build a [`User`] instance using the Builder parameters.
    ///
    /// # Errors
    /// This function will error out if the [`Transport`] or [`UserIdentity`] parameters are missing,
    /// as these make up the essence of a [`User`] and are required for any use case.
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
    /// ```
    pub fn build(self) -> Result<User<Trans>> {
        if self.id.is_none() {
            return err(UserIdentityMissing);
        }

        if self.transport.is_none() {
            return err(UserTransportMissing);
        }

        Ok(User {
            user: crate::api::ApiUser::new(self.id.unwrap()),
            transport: self.transport.unwrap(),
        })
    }

    /// Generates a new [`User`] implementation from the builder. If the announcement message generated
    /// by this instance matches that of an existing (and provided) announcement link, the user will
    /// sync to the latest state
    ///
    ///  # Arguements
    /// * `announcement` - An existing announcement message link for validation of ownership
    ///
    ///  # Errors
    /// This function will produce errors if the [`User`] tries to recover their instance without a
    /// proper [`UserIdentity`] or [`Transport`]. It can also return an error if there is an issue creating a new
    /// announcement message with the provided User configuration, or should the provided
    /// announcement link not be present on the transport layer.
    ///
    ///  # Example
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
    pub async fn recover(self, announcement: &Address) -> Result<User<Trans>> {
        let mut user = self.build()?;
        user.user.create_channel(0)?;

        let ann = user.user.announce().await?;
        let retrieved: Message = user.transport.recv_message(announcement).await?;
        assert_eq!(retrieved, ann.message);

        user.user.commit_wrapped(ann.wrapped, MsgInfo::Announce)?;
        user.sync_state().await?;
        Ok(user)
    }
}
