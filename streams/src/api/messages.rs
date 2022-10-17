// Rust
use alloc::{boxed::Box, collections::VecDeque, vec::Vec};
use core::{future::Future, pin::Pin};

// 3rd-party
use anyhow::Result;
use async_recursion::async_recursion;
use futures::{
    future,
    task::{Context, Poll},
    Stream, StreamExt, TryStream, TryStreamExt,
};
use hashbrown::HashMap;

// IOTA

// Streams
use lets::{
    address::{Address, MsgId},
    id::{Identifier, Permissioned},
    message::{Topic, TransportMessage, HDF},
    transport::Transport,
};

// Local
use crate::api::{
    message::{Message, MessageContent, Orphan},
    selector::Selector,
    user::User,
};

/// a [`Stream`] over the messages of the channel pending to be fetch from the transport
///
/// Use this stream to preorderly traverse the messages of the channel. This stream is usually
/// created from any type implementing [`IntoMessages`], calling its [`IntoMessages::messages()`]
/// method. The main method is [`Messages::next()`], which returns the next message in the channel
/// that is readable by the user.
///
/// This type implements [`futures::Stream`] and [`futures::TryStream`], therefore it can be used
/// with all the adapters provided by [`futures::StreamExt`] and [`futures::TryStreamExt`]:
///
/// ```
/// use futures::TryStreamExt;
///
/// use streams::{id::Ed25519, transport::utangle, Address, Result, User};
///
/// # use std::cell::RefCell;
/// # use std::rc::Rc;
/// # use streams::transport::bucket;
/// #
/// # #[tokio::main]
/// # async fn main() -> Result<()> {
/// # let test_transport = Rc::new(RefCell::new(bucket::Client::new()));
/// #
/// let author_seed = "cryptographically-secure-random-author-seed";
/// let author_transport: utangle::Client =
///     utangle::Client::new("https://chrysalis-nodes.iota.org");
/// #
/// # let test_author_transport = test_transport.clone();
/// #
/// let mut author = User::builder()
///     .with_identity(Ed25519::from_seed(author_seed))
/// #     .with_transport(test_author_transport)
///     .build();
///
/// let subscriber_seed = "cryptographically-secure-random-subscriber-seed";
/// let subscriber_transport: utangle::Client =
///     utangle::Client::new("https://chrysalis-nodes.iota.org");
/// #
/// # let subscriber_transport = test_transport.clone();
/// #
/// let mut subscriber = User::builder()
///     .with_identity(Ed25519::from_seed(subscriber_seed))
/// #    .with_transport(subscriber_transport)
///     .build();
///
/// let announcement = author.create_stream("BASE_BRANCH").await?;
/// subscriber.receive_message(announcement.address()).await?;
/// let first_packet = author
///     .send_signed_packet("BASE_BRANCH", b"public payload", b"masked payload")
///     .await?;
/// let second_packet = author
///     .send_signed_packet(
///         "BASE_BRANCH",
///         b"another public payload",
///         b"another masked payload",
///     )
///     .await?;
///
/// #
/// # let mut n = 0;
/// #
/// let mut messages = subscriber.messages();
/// while let Some(msg) = messages.try_next().await? {
///     println!(
///         "New message!\n\tPublic: {:?}\n\tMasked: {:?}\n",
///         msg.public_payload().unwrap_or(b"None"),
///         msg.masked_payload().unwrap_or(b"None")
///     );
/// #
/// #   n += 1;
/// #
/// }
/// #
/// # assert_eq!(n, 2);
/// # Ok(())
/// # }
/// ```
///
/// # Technical Details
/// This [`Stream`] makes sure the messages are traversed in topological order (preorder). This
/// means any parent message is yielded before its childs. As a consequence, there might be multiple
/// transport calls before a message is yielded, and several messages can be accumulated in memory
/// until their turn. Therefore, some jitter might be expected, with a worst case of fetching all
/// the messages before any is yielded.
///
/// After the last currently available message has been returned, [`Messages::next()`] returns
/// `None`, at which point the [`StreamExt`] and [`TryStreamExt`] methods will consider the
/// [`Stream`] finished and stop iterating. It is safe to continue calling [`Messages::next()`] or
/// any method from [`StreamExt`] and [`TryStreamExt`] polling for new messages.
///
/// Being a [`futures::Stream`] that fetches data from an external source, it's naturally defined as
/// a [`futures::TryStream`], which means it returns a [`Result`] wrapping the `UnwrappedMessage`.
/// In the event of a network failure, [`Messages::next()`] will return `Err`. It is strongly
/// suggested that, when suitable, use the methods in [`futures::TryStreamExt`] to make the
/// error-handling much more ergonomic (with the use of `?`) and shortcircuit the
/// [`futures::Stream`] on the first error.
pub struct Messages<'a, T>(PinBoxFut<'a, (MessagesState<'a, T>, Option<Result<Message>>)>);

type PinBoxFut<'a, T> = Pin<Box<dyn Future<Output = T> + 'a>>;

struct MessagesState<'a, T> {
    user: &'a mut User<T>,
    ids_stack: Vec<(Topic, Permissioned<Identifier>, usize)>,
    msg_queue: HashMap<MsgId, VecDeque<(MsgId, TransportMessage)>>,
    stage: VecDeque<(MsgId, TransportMessage)>,
    successful_round: bool,
}

impl<'a, T> MessagesState<'a, T> {
    fn new(user: &'a mut User<T>) -> Self {
        Self {
            user,
            ids_stack: Vec::new(),
            msg_queue: HashMap::new(),
            stage: VecDeque::new(),
            successful_round: false,
        }
    }

    /// Fetch the next message of the channel
    ///
    /// See [`Messages`] documentation and examples for more details.
    #[async_recursion(?Send)]
    async fn next(&mut self) -> Option<Result<Message>>
    where
        T: for<'b> Transport<'b, Msg = TransportMessage>,
    {
        if let Some((relative_address, binary_msg)) = self.stage.pop_front() {
            // Drain stage if not empty...
            let address = Address::new(self.user.stream_address()?.base(), relative_address);
            match self.user.handle_message(address, binary_msg).await {
                Ok(Message {
                    header:
                        HDF {
                            linked_msg_address: Some(linked_msg_address),
                            ..
                        },
                    content:
                        MessageContent::Orphan(Orphan {
                            // Currently ignoring cursor, as `GenericUser::handle_message()` parses the whole binary
                            // message again this redundancy is acceptable in favour of
                            // avoiding carrying over the Spongos state within `Message`
                            message: orphaned_msg,
                            ..
                        }),
                    ..
                }) => {
                    // The message might be unreadable because it's predecessor might still be pending
                    // to be retrieved from the Tangle. We could defensively check if the predecessor
                    // is already present in the state, but we don't want to couple this iterator to
                    // a memory-intensive storage. Instead, we take the optimistic approach and store
                    // the msg for later if the handling has failed.
                    self.msg_queue
                        .entry(linked_msg_address)
                        .or_default()
                        .push_back((relative_address, orphaned_msg));

                    self.next().await
                }
                Ok(message) => {
                    // Check if message has descendants pending to process and stage them for processing
                    if let Some(msgs) = self.msg_queue.remove(&message.address().relative()) {
                        self.stage.extend(msgs);
                    }

                    Some(Ok(message))
                }
                // message-Handling errors are a normal execution path, just skip them
                Err(_e) => self.next().await,
            }
        } else {
            // Stage is empty, populate it with some more messages
            let (topic, publisher, cursor) = match self.ids_stack.pop() {
                Some(id_cursor) => id_cursor,
                None => {
                    // new round
                    self.successful_round = false;
                    self.ids_stack = self
                        .user
                        .cursors()
                        .filter(|(_, p, _)| !p.is_readonly())
                        .map(|(t, p, c)| (t.clone(), p.clone(), c))
                        .collect();
                    self.ids_stack.pop()?
                }
            };
            let base_address = self.user.stream_address()?.base();
            let rel_address = MsgId::gen(base_address, publisher.identifier(), &topic, cursor + 1);
            let address = Address::new(base_address, rel_address);

            match self.user.transport_mut().recv_message(address).await {
                Ok(msg) => {
                    self.stage.push_back((address.relative(), msg));
                    self.successful_round = true;
                    self.next().await
                }
                Err(_e) => {
                    // Message not found or network error. Right now we are not distinguishing
                    // between each case, so we must assume it's message not found.
                    // When we introduce typed error handling and are able to distinguish,
                    // Return Err(e) if error is network-related or any other transient error
                    if self.ids_stack.is_empty() && !self.successful_round {
                        // After trying all ids, none has produced an existing link, end of stream (for now...)
                        None
                    } else {
                        // At least one id is producing existing links. continue...
                        self.next().await
                    }
                }
            }
        }
    }
}

impl<'a, T> Messages<'a, T>
where
    T: for<'b> Transport<'b, Msg = TransportMessage>,
{
    pub(crate) fn new(user: &'a mut User<T>) -> Self {
        let mut state = MessagesState::new(user);
        Self(Box::pin(async move {
            let r = state.next().await;
            (state, r)
        }))
    }

    /// "Filter the stream of messages to only those that match the selectors, and return the result
    /// as a vector."
    /// A message is matched when at least one of the selectors is a match.
    ///
    /// Important to note is that the stream DISCARDS the messages that dont fit the criteria from
    /// the selectors.
    ///
    /// # Arguments
    ///
    /// * `selectors`: A list of selectors to filter the messages by.
    ///
    /// Returns:
    ///
    /// A vector of Messages.
    pub async fn from(&mut self, selectors: &[Selector]) -> Vec<Message> {
        StreamExt::filter(self, |x| match &x {
            Ok(m) => {
                for selector in selectors {
                    if selector.is(m) {
                        return future::ready(true);
                    }
                }
                future::ready(false)
            }
            Err(_) => future::ready(false),
        })
        .map(|x| x.unwrap())
        .collect::<Vec<_>>()
        .await
    }

    /// `next` is an async function that returns an Option of a Result of a Message
    ///
    /// Returns:
    ///
    /// A message
    pub async fn next(&mut self) -> Option<Result<Message>> {
        StreamExt::next(self).await
    }

    /// Start streaming from a particular message
    ///
    /// Once that message is fetched and yielded, the returned [`Stream`] will yield only
    /// descendants of that message.
    ///
    ///  See [example in `Messages`
    /// docs](struct.Messages.html#filter-the-messages-of-a-particular-branch) for more details.
    pub fn filter_branch<Fut>(
        self,
        predicate: impl FnMut(&Message) -> Fut + 'a,
    ) -> impl Stream<Item = Result<Message>> + 'a
    where
        Fut: Future<Output = Result<bool>> + 'a,
        Self: TryStream<Ok = Message, Error = anyhow::Error>,
    {
        self.try_skip_while(predicate)
            .scan(None, |branch_last_address, msg| {
                future::ready(Some(msg.map(|msg| {
                    let msg_linked_address = msg.header().linked_msg_address()?;
                    let branch_last_address = branch_last_address.get_or_insert(msg_linked_address);
                    if msg_linked_address == *branch_last_address {
                        *branch_last_address = msg.address().relative();
                        Some(msg)
                    } else {
                        None
                    }
                })))
            })
            .try_filter_map(future::ok)
    }
}

impl<'a, T> From<&'a mut User<T>> for Messages<'a, T>
where
    T: for<'b> Transport<'b, Msg = TransportMessage>,
{
    fn from(user: &'a mut User<T>) -> Self {
        Self::new(user)
    }
}

impl<'a, T> Stream for Messages<'a, T>
where
    T: for<'b> Transport<'b, Msg = TransportMessage>,
{
    type Item = Result<Message>;

    fn poll_next(mut self: Pin<&mut Self>, ctx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        match self.0.as_mut().poll(ctx) {
            Poll::Ready((mut state, result)) => {
                self.set(Messages(Box::pin(async move {
                    let r = state.next().await;
                    (state, r)
                })));
                Poll::Ready(result)
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

#[cfg(test)]
mod tests {
    use alloc::rc::Rc;
    use core::cell::RefCell;

    use lets::{address::Address, id::Ed25519, transport::bucket};

    use crate::{
        api::{
            message::{
                Message,
                MessageContent::{BranchAnnouncement, Keyload, SignedPacket},
            },
            user::User,
        },
        Result,
    };

    type Transport = Rc<RefCell<bucket::Client>>;

    #[tokio::test]
    async fn messages_awake_pending_messages_link_to_them_even_if_their_content_is_unreadable() -> Result<()> {
        let p = b"payload";
        let (mut author, mut subscriber1, announcement_link, transport) = author_subscriber_fixture().await?;

        let branch_1 = "BRANCH_1";
        let branch_announcement = author.new_branch("BASE_BRANCH", branch_1).await?;
        let keyload_1 = author.send_keyload_for_all_rw(branch_1).await?;
        subscriber1.sync().await?;
        let _packet_1 = subscriber1.send_signed_packet(branch_1, &p, &p).await?;
        // This packet will never be readable by subscriber2. However, she will still be able to progress
        // through the next messages
        let _packet_2 = subscriber1.send_signed_packet(branch_1, &p, &p).await?;

        let mut subscriber2 = subscriber_fixture("subscriber2", &mut author, announcement_link, transport).await?;

        author.sync().await?;

        // This packet has to wait in the `Messages::msg_queue` until `packet` is processed
        let keyload_2 = author.send_keyload_for_all_rw(branch_1).await?;

        subscriber1.sync().await?;
        let last_signed_packet = subscriber1.send_signed_packet(branch_1, &p, &p).await?;

        let msgs = subscriber2.fetch_next_messages().await?;
        assert_eq!(4, msgs.len()); // branch_announcement, keyload_1, keyload_2 and last signed packet
        assert!(matches!(
            msgs.as_slice(),
            &[
                Message {
                    address: address_0,
                    content: BranchAnnouncement(..),
                    ..
                },
                Message {
                    address: address_1,
                    content: Keyload(..),
                    ..
                },
                Message {
                    address: address_2,
                    content: Keyload(..),
                    ..
                },
                Message {
                    address: address_3,
                    content: SignedPacket(..),
                    ..
                }
            ]
            if address_0 == branch_announcement.address()
            && address_1 == keyload_1.address()
            && address_2 == keyload_2.address()
            && address_3 == last_signed_packet.address()
        ));

        Ok(())
    }

    /// Prepare a simple scenario with an author, a subscriber, a channel announcement and a bucket
    /// transport
    async fn author_subscriber_fixture() -> Result<(User<Transport>, User<Transport>, Address, Transport)> {
        let transport = Rc::new(RefCell::new(bucket::Client::new()));
        let mut author = User::builder()
            .with_identity(Ed25519::from_seed("author"))
            .with_transport(transport.clone())
            .build();
        let announcement = author.create_stream("BASE_BRANCH").await?;
        let subscriber =
            subscriber_fixture("subscriber", &mut author, announcement.address(), transport.clone()).await?;
        Ok((author, subscriber, announcement.address(), transport))
    }

    async fn subscriber_fixture(
        seed: &str,
        author: &mut User<Transport>,
        announcement_link: Address,
        transport: Transport,
    ) -> Result<User<Transport>> {
        let mut subscriber = User::builder()
            .with_identity(Ed25519::from_seed(seed))
            .with_transport(transport)
            .build();
        subscriber.receive_message(announcement_link).await?;
        let subscription = subscriber.subscribe().await?;
        author.receive_message(subscription.address()).await?;
        Ok(subscriber)
    }
}
