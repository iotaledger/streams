use crate::api::{
    tangle::{
        MsgInfo,
        Transport,
        User,
    },
    Address,
    Message,
    DefaultF,
};
use iota_streams_app::id::{
    Identifier,
    UserIdentity,
};
use iota_streams_core::Result;

/// Builder instance for a Streams User
pub struct UserBuilder<'a, Trans: Transport + Clone, F> {
//pub struct UserBuilder<'a, F> {

    /// Base Identity that will be used to Identifier a Streams User
    pub id: Option<UserIdentity<F>>,
    /// Alternate Identity that can be used to mask the direct Identity of a Streams User
    pub alias: Option<UserIdentity<F>>,
    /// Transport Client instance
    pub transport: Option<&'a Trans>,
    /// Represents whether the User Instance will automatically sync before each message operation
    pub auto_sync: bool,
}

impl<'a, Trans: Transport + Clone, F> Default for UserBuilder<'a, Trans, F> {
//impl<'a, F> Default for UserBuilder<'a, F> {
    fn default() -> Self {
        UserBuilder {
            id: None,
            alias: None,
            transport: None,
            auto_sync: true,
        }
    }
}

/// ## Author from Seed
/// ```
/// use iota_streams_app_channels::{
///     UserBuilder,
///     UserIdentity,
///     User,
/// };
///
/// #
/// # use std::cell::RefCell;
/// # use std::rc::Rc;
/// # use iota_streams_app_channels::api::tangle::BucketTransport;
/// # use iota_streams_core::Result;
/// #
/// # #[tokio::main]
/// # async fn main() -> Result<()> {
/// # let author_transport = Rc::new(RefCell::new(BucketTransport::new()));
/// # let author_seed = "cryptographically-secure-random-author-seed";
/// #
/// # let author_identity = UserIdentity::new(author_seed).await;
/// # let mut author = UserBuilder::new()
///     .with_identity(author_identity)
///     .with_transport(&author_transport)
///     .build();
///
/// # let announcement_link = author.send_announce().await?;
/// # Ok(())
/// # }
/// ```
///
/// ## Subscriber from PskId
/// ```
/// use iota_streams_app_channels::{
///     api::{
///         psk_from_seed,
///         pskid_from_psk,
///    },
///     UserBuilder,
///     UserIdentity,
///     User,
/// };
///
/// #
/// # use std::cell::RefCell;
/// # use std::rc::Rc;
/// # use iota_streams_app_channels::api::tangle::BucketTransport;
/// # use iota_streams_core::Result;
/// #
/// # #[tokio::main]
/// # async fn main() -> Result<()> {
/// # let test_transport = Rc::new(RefCell::new(BucketTransport::new()));
/// # let author_seed = "cryptographically-secure-random-author-seed";
/// #
/// # let author_identity = UserIdentity::new(author_seed).await;
/// # let mut author = UserBuilder::new()
///     .with_identity(author_identity)
///     .with_transport(&test_transport)
///     .build();
///
/// # let psk_seed = "seed-for-pre-shared-key";
/// # let psk = psk_from_seed(psk_seed.as_bytes());
/// # let pskid = pskid_from_psk(&psk);
///
/// # let announcement_link = author.send_announce().await?;
/// # author.store_psk(pskid, psk)?;
///
/// # let subscriber_identity = UserIdentity::new_from_psk(pskid, psk).await;
/// # let mut subscriber = UserBuilder::new()
///     .with_identity(subscriber_identity)
///     .with_transport(&test_transport)
///     .build();
///
/// # subscriber.receive_announcement(&announcement_link).await?;
///
/// # let (keyload_link, _sequence_link) = author.send_keyload_for_everyone(&announcement_link).await?;
/// # assert!(subscriber.receive_keyload(&keyload_link).await?, "Subscriber can't see Keyload");
///
/// # Ok(())
/// # }
/// ```

impl<'a, Trans: Transport> UserBuilder<'a, Trans, DefaultF> {
    /// Create a new User Builder instance
    pub fn new() -> Self {
        Self::default()
    }

    /// Inject Base Identity into the User Builder
    ///
    /// # Arguments
    /// * `id` - UserIdentity to be used for base identification of the Streams User
    pub fn with_identity(&mut self, id: UserIdentity<DefaultF>) -> &mut Self {
        self.id = Some(id);
        self
    }

    /// Inject Alternate Identity into the User Builder
    ///
    /// # Arguments
    /// * `alias` - UserIdentity to be used for alternate identification of the Streams User
    pub fn with_alias(&mut self, alias: UserIdentity<DefaultF>) -> &mut Self {
        self.alias = Some(alias);
        self
    }

    /// Inject Transport Client instance into the User Builder
    ///
    /// # Arguments
    /// * `transport` - Transport Client to be used by the Streams User
    pub fn with_transport(&mut self, transport: &'a Trans) -> &mut Self {
        self.transport = Some(transport);
        self
    }

    /// Set the auto-sync value of the User Builder
    ///
    /// # Arguments
    /// * `auto_sync` - True if the User should automatically perform synchronisation before operations
    pub fn with_auto_sync(&mut self, auto_sync: bool) -> &mut Self {
        self.auto_sync = auto_sync;
        self
    }

    /// Build a User instance using the Builder values.
    pub fn build(&mut self) -> User<Trans> {
        let mut user = User {
            user: crate::api::ApiUser::gen(self),
            transport: self.transport.unwrap().clone(),
        };
        // If User is using a Psk as their base Identifier,
        if let Identifier::PskId(pskid) = *user.user.id() {
            // Unwraps shouldn't fail here due to the user containing a PskId type
            user.store_psk(pskid, user.user.user_id.psk().unwrap()).unwrap();
        }
        user
    }

    /// Generates a new User implementation from the builder. If the announcement message generated
    /// by this instance matches that of an existing (and provided) announcement link, the user will
    /// sync to the latest state
    ///
    ///  # Arguements
    /// * `announcement` - An existing announcement message link for validation of ownership
    pub async fn recover(&mut self, announcement: &Address) -> Result<User<Trans>> {
        let mut user = self.build();
        user.user.create_channel(0)?;

        let ann = user.user.announce().await?;
        let retrieved: Message = user.transport.recv_message(announcement).await?;
        assert_eq!(retrieved, ann.message);

        user.user.commit_wrapped(ann.wrapped, MsgInfo::Announce)?;
        user.sync_state().await?;
        Ok(user)
    }
}
