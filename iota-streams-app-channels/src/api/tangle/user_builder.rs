use crate::api::{
    tangle::{
        Transport,
        User,
    },
    DefaultF,
};
use iota_streams_app::{
    id::{
        Identifier,
        UserIdentity,
    },
    transport::tangle::client::Client,
};
use std::mem::take;

/// Builder instance for a Streams User
pub struct UserBuilder<Trans: Transport, F> {
    /// Base Identity that will be used to Identifier a Streams User
    id: UserIdentity<F>,
    /// Alternate Identity that can be used to mask the direct Identity of a Streams User
    alias: Option<UserIdentity<F>>,
    /// Transport Client instance
    transport: Trans,
    /// Represents whether the User Instance will automatically sync before each message operation
    auto_sync: bool,
}

impl<Trans: Transport, F> Default for UserBuilder<Trans, F> {
    fn default() -> Self {
        UserBuilder {
            id: UserIdentity::default(),
            alias: None,
            transport: Trans::default(),
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
///     .with_transport(author_transport)
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
/// # let author_transport = test_transport.clone();
/// # let author_identity = UserIdentity::new(author_seed).await;
/// # let mut author = UserBuilder::new()
///     .with_identity(author_identity)
///     .with_transport(author_transport)
///     .build();
///
/// # let psk_seed = "seed-for-pre-shared-key";
/// # let psk = psk_from_seed(psk_seed.as_bytes());
/// # let pskid = pskid_from_psk(&psk);
///
/// # let announcement_link = author.send_announce().await?;
/// # author.store_psk(pskid, psk)?;
///
/// # let subscriber_transport = test_transport.clone();
/// # let subscriber_identity = UserIdentity::new_from_psk(pskid, psk).await;
/// # let mut subscriber = UserBuilder::new()
///     .with_identity(subscriber_identity)
///     .with_transport(subscriber_transport)
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
impl UserBuilder<Client, DefaultF> {
    /// Inject Tangle Client instance into the User Builder by URL
    ///
    /// # Arguments
    /// * `url` - Tangle Node URL string
    pub fn with_node_url(&mut self, url: &str) -> &mut Self {
        self.transport = Client::new_from_url(url);
        self
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
    pub fn with_identity(&mut self, id: UserIdentity<DefaultF>) -> &mut Self {
        self.id = id;
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
    pub fn with_transport(&mut self, transport: Trans) -> &mut Self {
        self.transport = transport;
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
            user: crate::api::User::gen(take(&mut self.id), take(&mut self.alias), self.auto_sync),
            transport: self.transport.clone(),
        };
        // If User is using a Psk as their base Identifier,
        if let Identifier::PskId(pskid) = *user.user.id() {
            // Unwraps shouldn't fail here due to the user containing a PskId type
            user.store_psk(pskid, user.user.user_id.psk().unwrap()).unwrap();
        }
        user
    }
}
