use crate::{Error, Result, SendResponse, User};
use lets::{
    message::{Topic, TransportMessage},
    transport::Transport,
};

/// A builder for creating messages for transport
pub struct MessageBuilder<'a, P, Trans> {
    /// A User Client to send the message from
    user: &'a mut User<Trans>,
    /// Whether or not the message payload will be masked in transit (defaults to masked)
    private: bool,
    /// Whether or not the message will be signed by the user sending (defaults to unsigned)
    signed: bool,
    /// The Topic of the branch the message will be sent to (defaults to the base branch)
    topic: Topic,
    /// A payload to be sent to the channel
    payload: P,
}

impl<'a, P, Trans> MessageBuilder<'a, P, Trans> {
    /// Creates a new MessageBuilder from an existing User Client
    ///
    /// # Arguments
    /// * user - User Client that will send the message
    pub fn new(user: &'a mut User<Trans>) -> Self
    where
        P: Default,
    {
        let topic = user.base_branch().clone();
        MessageBuilder {
            user,
            private: true,
            signed: false,
            topic,
            payload: P::default(),
        }
    }

    /// Sets the private flag to false, so the message will not be masked in transit
    pub fn public(mut self) -> Self {
        self.private = false;
        self
    }

    /// Sets the signed flag to true, so the User will sign the message
    pub fn signed(mut self) -> Self {
        self.signed = true;
        self
    }

    /// Inject the data payload into the builder. The payload cannot be empty and must be able to be
    /// referenced as an unsigned byte array.
    ///
    /// # Arguments
    /// * payload - The data payload that will be sent
    pub fn with_payload(mut self, payload: P) -> Self
    where
        P: AsRef<[u8]>,
    {
        self.payload = payload;
        self
    }

    /// Inject the Topic of the branch into the builder. The default topic is the base branch topic
    /// of the User Client.
    ///
    /// # Arguments
    /// * topic - The topic of the branch the message will be sent to
    pub fn with_topic<Top: Into<Topic>>(mut self, topic: Top) -> Self {
        self.topic = topic.into();
        self
    }

    /// Sends the message payload to the specified branch using the User Client. If the message is
    /// signed, the message will be sent as a Signed Packet, and if not, it will be sent as a
    /// Tagged Packet.
    ///
    ///
    /// # Examples
    /// ## Send Signed Message
    /// ```
    /// # use streams::{id::Ed25519, transport::bucket, User, Result};
    /// #
    /// # #[tokio::main]
    /// # async fn main() -> Result<()> {
    /// # let user_seed = "cryptographically-secure-random-user-seed";
    /// # let mut user = User::builder()
    /// #    .with_identity(Ed25519::from_seed(user_seed))
    /// #    .with_transport(bucket::Client::new())
    /// #    .build();
    /// #
    /// let topic = "Branch 1";
    /// # user.create_stream(topic).await?;
    /// let payload = "A Data Payload";
    ///
    /// let message = user
    ///     .message()
    ///     .with_topic(topic)
    ///     .with_payload(payload)
    ///     .signed()
    ///     .send()
    ///     .await?;
    ///
    /// # Ok(())
    /// # }
    /// ```
    pub async fn send<TSR>(self) -> Result<SendResponse<TSR>>
    where
        P: AsRef<[u8]>,
        Trans: for<'b> Transport<'b, Msg = TransportMessage, SendResponse = TSR>,
    {
        if self.payload.as_ref().is_empty() {
            return Err(Error::PayloadEmpty);
        }

        let mut public: &[u8] = &[];
        let mut private: &[u8] = &[];

        if self.private {
            private = self.payload.as_ref()
        } else {
            public = self.payload.as_ref()
        }

        if self.signed {
            self.user.send_signed_packet(self.topic, public, private).await
        } else {
            self.user.send_tagged_packet(self.topic, public, private).await
        }
    }
}

#[cfg(test)]
mod message_builder_tests {
    use crate::{api::message_builder::MessageBuilder, User};
    use lets::{id::Ed25519, message::Topic, transport::bucket};

    const BASE_BRANCH: &str = "Base Branch";

    async fn make_user() -> User<bucket::Client> {
        let mut user = User::builder()
            .with_transport(bucket::Client::new())
            .with_identity(Ed25519::from_seed("user seed"))
            .build();

        user.create_stream(BASE_BRANCH).await.unwrap();

        user
    }

    #[tokio::test]
    async fn make_message() {
        let topic = "A message topic";
        let payload = "A payload";
        let raw_payload = [80_u8, 97, 121, 108, 111, 97, 100];

        let mut user = make_user().await;
        user.new_branch(BASE_BRANCH, topic).await.unwrap();

        let str_message = MessageBuilder::new(&mut user).with_payload(payload).signed().public();

        assert!(!str_message.private);
        assert!(str_message.signed);
        assert_eq!(Topic::from(BASE_BRANCH), str_message.topic);
        assert_eq!(payload, str_message.payload);

        let raw_message = MessageBuilder::new(&mut user)
            .with_payload(raw_payload)
            .with_topic(topic);

        assert!(raw_message.private);
        assert!(!raw_message.signed);
        assert_eq!(Topic::from(topic), raw_message.topic);
        assert_eq!(raw_payload, raw_message.payload);
    }

    #[tokio::test]
    async fn empty_payload_message() {
        let mut user = make_user().await;

        let message = user.message().with_payload(vec![]).send().await;

        assert!(message.is_err());
    }

    #[tokio::test]
    async fn send_signed_messages() {
        let mut user = make_user().await;
        let priv_payload = "A Private Payload";
        let pub_payload = "A Public Payload";

        let private_msg = MessageBuilder::new(&mut user)
            .with_payload(priv_payload)
            .signed()
            .send()
            .await
            .unwrap();

        let public_msg = MessageBuilder::new(&mut user)
            .with_payload(pub_payload)
            .signed()
            .public()
            .send()
            .await
            .unwrap();

        let received_private_msg = user.receive_message(private_msg.address()).await.unwrap();

        let received_public_msg = user.receive_message(public_msg.address()).await.unwrap();

        assert!(received_private_msg.is_signed_packet());
        assert_eq!(
            received_private_msg.as_signed_packet().unwrap().masked_payload,
            priv_payload.as_bytes()
        );
        assert!(
            received_private_msg
                .as_signed_packet()
                .unwrap()
                .public_payload
                .is_empty()
        );

        assert!(received_public_msg.is_signed_packet());
        assert_eq!(
            received_public_msg.as_signed_packet().unwrap().public_payload,
            pub_payload.as_bytes()
        );
        assert!(
            received_public_msg
                .as_signed_packet()
                .unwrap()
                .masked_payload
                .is_empty()
        );
    }

    #[tokio::test]
    async fn send_tagged_messages() {
        let mut user = make_user().await;
        let priv_payload = "A Private Payload";
        let pub_payload = "A Public Payload";

        let private_msg = MessageBuilder::new(&mut user)
            .with_payload(priv_payload)
            .send()
            .await
            .unwrap();

        let public_msg = MessageBuilder::new(&mut user)
            .with_payload(pub_payload)
            .public()
            .send()
            .await
            .unwrap();

        let received_private_msg = user.receive_message(private_msg.address()).await.unwrap();

        let received_public_msg = user.receive_message(public_msg.address()).await.unwrap();

        assert!(received_private_msg.is_tagged_packet());
        assert_eq!(
            received_private_msg.as_tagged_packet().unwrap().masked_payload,
            priv_payload.as_bytes()
        );
        assert!(
            received_private_msg
                .as_tagged_packet()
                .unwrap()
                .public_payload
                .is_empty()
        );

        assert!(received_public_msg.is_tagged_packet());
        assert_eq!(
            received_public_msg.as_tagged_packet().unwrap().public_payload,
            pub_payload.as_bytes()
        );
        assert!(
            received_public_msg
                .as_tagged_packet()
                .unwrap()
                .masked_payload
                .is_empty()
        );
    }
}
