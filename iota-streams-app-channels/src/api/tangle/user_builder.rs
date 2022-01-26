use std::mem::take;
use iota_streams_app::id::{Identifier, Identity};
use iota_streams_app::transport::tangle::client::Client;
use crate::api::DefaultF;
use crate::api::tangle::{Transport, User};

pub struct UserBuilder<Trans: Transport, F> {
    id: Identity<F>,
    alias: Option<Identity<F>>,
    transport: Trans,
    auto_sync: bool
}

impl<Trans: Transport, F> Default for UserBuilder<Trans, F> {
    fn default() -> Self {
        UserBuilder {
            id: Identity::default(),
            alias: None,
            transport: Trans::default(),
            auto_sync: true,
        }
    }
}

impl UserBuilder<Client, DefaultF> {
    pub fn with_node_url(&mut self, url: &str) -> &mut Self {
        self.transport = Client::new_from_url(url);
        self
    }
}

impl<Trans: Transport> UserBuilder<Trans, DefaultF> {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_identity(&mut self, id: Identity<DefaultF>) -> &mut Self {
        self.id = id;
        self
    }

    pub fn with_alias(&mut self, alias: Identity<DefaultF>) -> &mut Self {
        self.alias = Some(alias);
        self
    }

    pub fn with_transport(&mut self, transport: Trans) -> &mut Self {
        self.transport = transport;
        self
    }

    pub fn with_auto_sync(&mut self, auto_sync: bool) -> &mut Self {
        self.auto_sync = auto_sync;
        self
    }

    pub fn build(&mut self) -> User<Trans> {
        let mut user = User {
            user: crate::api::user::User::gen(take(&mut self.id), take(&mut self.alias), self.auto_sync),
            transport: self.transport.clone()
        };
        if let Identifier::PskId(pskid) = user.user.user_id.id {
            // Unwrap shouldn't fail here due to the user containing a PskId type
            user.store_psk(pskid, user.user.user_id.get_psk().unwrap()).unwrap();
        }
        user
    }
}




