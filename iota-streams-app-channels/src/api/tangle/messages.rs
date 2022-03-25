use core::{
    future::Future,
    pin::Pin,
};

use async_recursion::async_recursion;
use futures::{
    future,
    task::{
        Context,
        Poll,
    },
    Stream,
    StreamExt,
    TryStreamExt,
};
use iota_streams_app::{
    id::Identifier,
    message::LinkedMessage,
};
use iota_streams_core::{
    prelude::{
        Box,
        HashMap,
        Vec,
        VecDeque,
    },
    Result,
};

use super::{
    Address,
    BinaryMessage,
    Cursor,
    MessageContent,
    Transport,
    UnwrappedMessage,
    User,
};

// TODO: aclarative comments
// TODO: Documentation
// TODO: backwards stream
// TODO: next_msg in C bindings
// TODO: Consider renaming msgs => messages
// TODO: run examples in actions

pub trait IntoMessages<Trans> {
    fn messages(&mut self) -> Messages<'_, Trans>
    where
        Trans: Transport;
}

/// a [`Stream`] over the messages of the channel pending to be fetch from the transport
///
/// Use this stream to preorderly traverse the messages of the channel. This stream is usually
/// created from any type implementing [`IntoMessages`], calling its [`IntoMessages::messages()`] method.
/// The main method is [`Messages::next()`], which returns the next message in the channel that is readable
/// by the user.
///
/// This type implements [`futures::Stream`] and [`futures::TryStream`], therefore it can be used with all the adapters
/// provided by [`futures::StreamExt`] and [`futures::TryStreamExt`]:
///
/// ## Iterate over the pending messages
/// ```
/// use iota_streams_app_channels::{
///     api::tangle::futures::TryStreamExt,
///     Address,
///     Bytes,
///     MessageContent,
///     Tangle,
///     UnwrappedMessage,
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
/// #
/// let author_seed = "cryptographically-secure-random-author-seed";
/// let author_transport = Tangle::new_from_url("https://chrysalis-nodes.iota.org");
/// #
/// # let author_transport = test_transport.clone();
/// #
/// let mut author = User::new(author_seed, author_transport).await;
///
/// let subscriber_seed = "cryptographically-secure-random-subscriber-seed";
/// let subscriber_transport = Tangle::new_from_url("https://chrysalis-nodes.iota.org");
/// #
/// # let subscriber_transport = test_transport.clone();
/// #
/// let mut subscriber = User::new(subscriber_seed, subscriber_transport).await;
///
/// let announcement_link = author.send_announce().await?;
/// subscriber.receive_announcement(&announcement_link).await?;
/// let subscription_link = subscriber.send_subscribe(&announcement_link).await?;
/// author.receive_subscribe(&subscription_link).await?;
/// let (keyload_link, sequence_link) = author.send_keyload_for_everyone(&announcement_link).await?;
/// let (first_packet_link, sequence_link) = author
///     .send_signed_packet(&keyload_link, &b"public payload".into(), &b"masked payload".into())
///     .await?;
/// let (second_packet_link, sequence_link) = author
///     .send_signed_packet(
///         &first_packet_link,
///         &b"another public payload".into(),
///         &b"another masked payload".into(),
///     )
///     .await?;
///
/// #
/// # let mut n = 0;
/// #
/// let mut messages = subscriber.messages();
/// while let Some(msg) = messages.try_next().await? {
///     println!(
///         "New message!\n\tPublic: {}\n\tMasked: {}\n",
///         msg.body.public_payload().and_then(Bytes::as_str).unwrap_or("None"),
///         msg.body.masked_payload().and_then(Bytes::as_str).unwrap_or("None")
///     );
/// #
/// #   n += 1;
/// #
/// }
/// #
/// # assert_eq!(n, 3);
/// # Ok(())
/// # }
/// ```
///
/// ## Collect all the pending messages into a Vector (or any other collection type)
/// ```
/// use iota_streams_app_channels::{
///     api::tangle::futures::TryStreamExt,
///     Address,
///     MessageContent,
///     Tangle,
///     UnwrappedMessage,
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
/// #
/// let author_seed = "cryptographically-secure-random-author-seed";
/// let author_transport = Tangle::new_from_url("https://chrysalis-nodes.iota.org");
/// #
/// # let author_transport = test_transport.clone();
/// #
/// let mut author = User::new(author_seed, author_transport).await;
///
/// let subscriber_seed = "cryptographically-secure-random-subscriber-seed";
/// let subscriber_transport = Tangle::new_from_url("https://chrysalis-nodes.iota.org");
/// #
/// # let subscriber_transport = test_transport.clone();
/// #
/// let mut subscriber = User::new(subscriber_seed, subscriber_transport).await;
///
/// let announcement_link = author.send_announce().await?;
/// subscriber.receive_announcement(&announcement_link).await?;
/// let subscription_link = subscriber.send_subscribe(&announcement_link).await?;
/// author.receive_subscribe(&subscription_link).await?;
/// let (keyload_link, sequence_link) = author.send_keyload_for_everyone(&announcement_link).await?;
/// let (first_packet_link, sequence_link) = author
///     .send_signed_packet(&keyload_link, &b"public payload".into(), &b"masked payload".into())
///     .await?;
/// let (second_packet_link, sequence_link) = author
///     .send_signed_packet(
///         &first_packet_link,
///         &b"another public payload".into(),
///         &b"another masked payload".into(),
///     )
///     .await?;
///
/// let messages: Vec<UnwrappedMessage> = subscriber.messages().try_collect().await?;
/// assert_eq!(
///     messages,
///     vec![
///         UnwrappedMessage::new(keyload_link, announcement_link, MessageContent::new_keyload()),
///         UnwrappedMessage::new(
///             first_packet_link,
///             keyload_link,
///             MessageContent::new_signed_packet(author.id().clone(), b"public payload", b"masked payload")
///         ),
///         UnwrappedMessage::new(
///             second_packet_link,
///             first_packet_link,
///             MessageContent::new_signed_packet(
///                 author.id().clone(),
///                 b"another public payload",
///                 b"another masked payload"
///             )
///         ),
///     ]
/// );
/// #
/// # Ok(())
/// # }
/// ```
///
/// ## Iterate over the channel messages indefinitely
///
/// ### Author
/// ```
/// # use core::cell::RefCell;
/// use iota_streams_app_channels::{
///     api::tangle::futures::TryStreamExt,
///     Bytes,
///     Tangle,
///     User,
/// };
/// # use iota_streams_app_channels::api::tangle::BucketTransport;
/// # use iota_streams_core::{prelude::Rc, Result};
///
/// # #[tokio::main]
/// # async fn main() -> Result<()> {
/// # let test_transport = Rc::new(RefCell::new(BucketTransport::new()));
/// #
/// let author_seed = "cryptographically-secure-random-author-seed";
/// let author_transport = Tangle::new_from_url("https://chrysalis-nodes.iota.org");
/// #
/// # let author_transport = test_transport.clone();
/// #
/// let mut author = User::new(author_seed, author_transport).await;
/// let announcement_link = author.send_announce().await?;
/// let shareable_announcement_link = announcement_link.to_string();
///
/// # let subscriber_seed = "cryptographically-secure-random-subscriber-seed";
/// # let subscriber_transport = Tangle::new_from_url("https://chrysalis-nodes.iota.org");
/// #
/// # let subscriber_transport = test_transport.clone();
/// #
/// # let mut subscriber = User::new(subscriber_seed, subscriber_transport).await;
/// # let announcement_link = shareable_announcement_link.parse().expect("parsing announcement link");
/// # subscriber.receive_announcement(&announcement_link).await?;
/// # let subscription_link = subscriber.send_subscribe(&announcement_link).await?;
/// #
/// # let subscriber_process = async move {
/// #
/// # let mut n = 0;
/// # let mut messages = subscriber.messages();
/// # loop {
/// #   if n >= 6 {
/// #       break;
/// #   }
/// #   if let Some(msg) = messages.try_next().await? {
/// #       println!(
/// #           "New message!\n\tPublic: {}\n\tMasked: {}\n",
/// #           msg.body.public_payload().and_then(Bytes::as_str).unwrap_or("None"),
/// #           msg.body.masked_payload().and_then(Bytes::as_str).unwrap_or("None")
/// #       );
/// #     n += 1;
/// #   }
/// # }
/// #
/// # let r: Result<()> = Ok(());
/// # r
/// # };
/// #
/// // The subscription link is provided by the subscriber once she sends the subscription message
/// let shareable_susbcription_link = "<subscription-link>";
/// # let shareable_subscription_link = subscription_link.to_string();
/// let subscription_link = shareable_subscription_link.parse().expect("parsing subscription link");
/// author.receive_subscribe(&subscription_link).await?;
/// let (keyload_link, sequence_link) = author.send_keyload_for_everyone(&announcement_link).await?;
/// let mut last_link = keyload_link;
/// #
/// # let author_process = async move {
/// #
/// loop {
/// #
/// # break;
/// # }
/// # for _ in 0..5 {
/// #
///     let (packet_link, sequence_link) = author
///         .send_signed_packet(&last_link, &b"public payload".into(), &b"masked payload".into())
///         .await?;
///     last_link = packet_link;
/// }
/// #
/// # let r: Result<()> = Ok(());
/// # r
/// # };
/// #
/// # author_process.await?;
/// # subscriber_process.await?;
/// # Ok(())
/// # }
/// #
/// ```
///
/// # Subscriber
/// ```
/// # use core::cell::RefCell;
/// use iota_streams_app_channels::{
///     api::tangle::futures::TryStreamExt,
///     Bytes,
///     Tangle,
///     User,
/// };
/// # use iota_streams_app_channels::api::tangle::BucketTransport;
/// # use iota_streams_core::{prelude::Rc, Result};
/// #
/// # #[tokio::main]
/// # async fn main() -> Result<()> {
/// # let test_transport = Rc::new(RefCell::new(BucketTransport::new()));
/// #
/// # let author_seed = "cryptographically-secure-random-author-seed";
/// # let author_transport = Tangle::new_from_url("https://chrysalis-nodes.iota.org");
/// #
/// # let author_transport = test_transport.clone();
/// #
/// # let mut author = User::new(author_seed, author_transport).await;
/// # let announcement_link = author.send_announce().await?;
///
/// let subscriber_seed = "cryptographically-secure-random-subscriber-seed";
/// let subscriber_transport = Tangle::new_from_url("https://chrysalis-nodes.iota.org");
/// #
/// # let subscriber_transport = test_transport.clone();
/// #
/// let mut subscriber = User::new(subscriber_seed, subscriber_transport).await;
///
/// // Announcement link is provided by author
/// let shareable_announcement_link = "<channel-announcement-link>";
/// # let shareable_announcement_link = announcement_link.to_string();
/// let announcement_link = shareable_announcement_link.parse().expect("parsing announcement link");
/// subscriber.receive_announcement(&announcement_link).await?;
/// let subscription_link = subscriber.send_subscribe(&announcement_link).await?;
/// let shareable_subscription_link = subscription_link.to_string();
/// #
/// # let subscriber_process = async move {
/// #
/// # let mut n = 0;
///
/// let mut messages = subscriber.messages();
/// loop {
/// #   if n >= 6 {
/// #       break;
/// #   }
///     if let Some(msg) = messages.try_next().await? {
///         println!(
///             "New message!\n\tPublic: {}\n\tMasked: {}\n",
///             msg.body.public_payload().and_then(Bytes::as_str).unwrap_or("None"),
///             msg.body.masked_payload().and_then(Bytes::as_str).unwrap_or("None")
///         );
/// #       n += 1;
///     }
/// }
/// #
/// # let r: Result<()> = Ok(());
/// # r
/// # };
/// #
/// # // The subscription link is provided by the subscriber once she sends the subscription message
/// # let subscription_link = shareable_subscription_link.parse().expect("parsing subscription link");
/// # author.receive_subscribe(&subscription_link).await?;
/// # let (keyload_link, sequence_link) = author.send_keyload_for_everyone(&announcement_link).await?;
/// # let mut last_link = keyload_link;
/// #
/// # let author_process = async move {
/// #
/// # loop {
/// #
/// # break;
/// # }
/// # for _ in 0..5 {
/// #
/// #     let (packet_link, sequence_link) = author
/// #         .send_signed_packet(&last_link, &b"public payload".into(), &b"masked payload".into())
/// #         .await?;
/// #     last_link = packet_link;
/// # }
/// #
/// # let r: Result<()> = Ok(());
/// # r
/// # };
/// #
/// # author_process.await?;
/// # subscriber_process.await?;
/// # Ok(())
/// # }
/// #
/// ```
/// ## Filter the messages of a particular branch
/// ```
/// use iota_streams_app_channels::{
///     api::tangle::futures::{
///         future,
///         StreamExt,
///         TryStreamExt,
///     },
///     Address,
///     Bytes,
///     MessageContent,
///     Tangle,
///     UnwrappedMessage,
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
/// #
/// let author_seed = "cryptographically-secure-random-author-seed";
/// let author_transport = Tangle::new_from_url("https://chrysalis-nodes.iota.org");
/// #
/// # let author_transport = test_transport.clone();
/// #
/// let mut author = User::new(author_seed, author_transport).await;
///
/// let subscriber_seed = "cryptographically-secure-random-subscriber-seed";
/// let subscriber_transport = Tangle::new_from_url("https://chrysalis-nodes.iota.org");
/// #
/// # let subscriber_transport = test_transport.clone();
/// #
/// let mut subscriber = User::new(subscriber_seed, subscriber_transport).await;
///
/// let announcement_link = author.send_announce().await?;
/// subscriber.receive_announcement(&announcement_link).await?;
/// let subscription_link = subscriber.send_subscribe(&announcement_link).await?;
/// author.receive_subscribe(&subscription_link).await?;
///
/// let (first_keyload_link, _sequence_link) = author.send_keyload_for_everyone(&announcement_link).await?;
/// let (tag_first_branch_link, _sequence_link) = author
///     .send_signed_packet(&first_keyload_link, &Default::default(), &b"branch 1".into())
///     .await?;
/// let (first_packet_first_branch_link, _sequence_link) = author
///     .send_signed_packet(
///         &tag_first_branch_link,
///         &Default::default(),
///         &b"masked payload in branch 1".into(),
///     )
///     .await?;
/// let (second_packet_first_branch_link, _sequence_link) = author
///     .send_signed_packet(
///         &first_packet_first_branch_link,
///         &Default::default(),
///         &b"another masked payload in branch 1".into(),
///     )
///     .await?;
///
/// let (second_keyload_link, sequence_link) = author.send_keyload_for_everyone(&announcement_link).await?;
/// let (tag_second_branch_link, _sequence_link) = author
///     .send_signed_packet(&second_keyload_link, &Default::default(), &b"branch 2".into())
///     .await?;
/// let (first_packet_second_branch_link, sequence_link) = author
///     .send_signed_packet(
///         &tag_second_branch_link,
///         &Default::default(),
///         &b"masked payload in branch 2".into(),
///     )
///     .await?;
/// let (second_packet_second_branch_link, sequence_link) = author
///     .send_signed_packet(
///         &first_packet_second_branch_link,
///         &Default::default(),
///         &b"another masked payload in branch 2".into(),
///     )
///     .await?;
///
/// let messages: Vec<UnwrappedMessage> = subscriber
///     .messages()
///     .filter_branch(|msg| {
///         future::ok(
///             msg.body
///                 .masked_payload()
///                 .and_then(Bytes::as_str)
///                 .map(|payload| payload != "branch 2")
///                 .unwrap_or(true),
///         )
///     })
///     .skip(1) // Skip tag message
///     .try_collect()
///     .await?;
///
/// assert_eq!(
///     messages,
///     vec![
///         UnwrappedMessage::new(
///             first_packet_second_branch_link,
///             tag_second_branch_link,
///             MessageContent::new_signed_packet(author.id().clone(), b"", b"masked payload in branch 2")
///         ),
///         UnwrappedMessage::new(
///             second_packet_second_branch_link,
///             first_packet_second_branch_link,
///             MessageContent::new_signed_packet(author.id().clone(), b"", b"another masked payload in branch 2")
///         ),
///     ]
/// );
/// # Ok(())
/// # }
/// ```
/// ## Iterate until finding a particular message
/// See [Filter the Messages of a Particular Branch example](#filter-the-messages-of-a-particular-branch)
/// ## Iterate over multiple channels at the same time
/// **TODO signal synchronization using zip**
/// ## Concatenate payloads
/// **TODO accounting using fold**
/// ## Wait over multiple channels concurrently and handle the first that has a new message ready
/// **TODO RPC server using select**
///
/// # Technical Details
/// This [`Stream`] makes sure the messages are traversed in topological order (preorder). This means any parent
/// message is yielded before its childs. As a consequence, there might be multiple transport
/// calls before a message is yielded, and several messages can be accumulated in memory until their turn.
/// Therefore, some jitter might be expected, with a worst case of fetching all the messages before any is
/// yielded.
///
/// Sequence messages and unreadable messages are not yielded, as they are not considered to add any end-user value.
/// Particularly unreadable messages are optimistically considered children waiting for their parent, thus accumulated
/// in memory and reprocessed instead of being yielded.
///
/// After the last currently available message has been returned, [`Messages::next()`] returns `None`, at which point
/// the [`StreamExt`] and [`TryStreamExt`] methods will consider the [`Stream`] finished and stop iterating.
/// It is safe to continue calling [`Messages::next()`] or any method from [`StreamExt`] and [`TryStreamExt`] polling
/// for new messages.
///
/// Being a [`futures::Stream`] that fetches data from an external source, it's naturally defined as a
/// [`futures::TryStream`], which means it returns a [`Result`] wrapping the [`UnwrappedMessage`]. In the event of a
/// network failure, [`Messages::next()`] will return `Err`. It is strongly suggested that, when suitable, use the
/// methods in [`futures::TryStreamExt`] to make the error-handling much more ergonomic (with the use of `?`) and
/// shortcircuit the [`futures::Stream`] on the first error.
pub struct Messages<'a, Trans>(PinBoxFut<'a, (MessagesState<'a, Trans>, Option<Result<UnwrappedMessage>>)>);

type PinBoxFut<'a, T> = Pin<Box<dyn Future<Output = T> + 'a>>;

pub struct MessagesState<'a, Trans> {
    user: &'a mut User<Trans>,
    ids_stack: Vec<(Identifier, Cursor<Address>)>,
    msg_queue: HashMap<Address, VecDeque<BinaryMessage>>,
    stage: VecDeque<BinaryMessage>,
    successful_round: bool,
}

impl<'a, Trans> MessagesState<'a, Trans> {
    pub fn new(user: &'a mut User<Trans>) -> Self {
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
    pub async fn next(&mut self) -> Option<Result<UnwrappedMessage>>
    where
        Trans: Transport,
    {
        if let Some(binary_msg) = self.stage.pop_front() {
            // Drain stage if not empty...
            match self.user.handle_message(&binary_msg, true).await {
                Ok(UnwrappedMessage {
                    body: MessageContent::Unreadable(unreadable_binary),
                    prev_link,
                    link,
                }) => {
                    // The message might be unreadable because it's predecessor might still be pending
                    // to be retrieved from the Tangle. We could defensively check if the predecessor
                    // is already present in the state, but we don't want to couple this iterator to
                    // a memory-intensive storage. Instead, we take the optimistic approach and store
                    // the msg for later if the handling has failed.
                    self.msg_queue
                        .entry(prev_link)
                        .or_default()
                        .push_back(unreadable_binary);

                    // If the handled message is a sequence_message, unreadable_binary is its referenced msg,
                    // not the sequence msg itself. However, messages can be linked to either. The sequence
                    // message has already been read successfuly, thus we need to awake any messages linked to it.
                    // Currently inferring it's a sequence message by checking if the original_link
                    // is different from resulting readable_msg link:
                    if *binary_msg.link() != link {
                        if let Some(msgs) = self.msg_queue.remove(binary_msg.link()) {
                            self.stage.extend(msgs);
                        }
                    }

                    self.next().await
                }
                Ok(readable_msg) => {
                    // Check if message has descendants pending to process and stage them for processing
                    if let Some(msgs) = self.msg_queue.remove(readable_msg.link()) {
                        self.stage.extend(msgs);
                    }

                    // If the handled message is a sequence_message, readable_msg is its referenced msg,
                    // not the sequence msg itself. However, messages can be linked to either.
                    // Currently inferring it's a sequence message by checking if the original_link
                    // is different from resulting readable_msg link:
                    if binary_msg.link() != readable_msg.link() {
                        if let Some(msgs) = self.msg_queue.remove(binary_msg.link()) {
                            self.stage.extend(msgs);
                        }
                    }

                    Some(Ok(readable_msg))
                }
                // message-Handling errors are a normal execution path, just skip them
                Err(_e) => self.next().await,
            }
        } else {
            // Stage is empty, populate it with some more messages
            let (_id, Cursor { link, .. }) = match self.ids_stack.pop() {
                Some(id_cursor) => id_cursor,
                None => {
                    let mut id_cursors = self.user.gen_next_msg_addresses();
                    let last = id_cursors.pop()?;
                    self.ids_stack = id_cursors;
                    self.successful_round = false; // new round
                    last
                }
            };
            match self.user.transport.recv_message(&link).await {
                Ok(msg) => {
                    self.stage.push_back(msg);
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

impl<'a, Trans> Messages<'a, Trans>
where
    Trans: Transport,
{
    pub fn new(user: &'a mut User<Trans>) -> Self {
        let mut state = MessagesState::new(user);
        Self(Box::pin(async move {
            let r = state.next().await;
            (state, r)
        }))
    }

    pub async fn next(&mut self) -> Option<Result<UnwrappedMessage>> {
        StreamExt::next(self).await
    }

    /// Start streaming from a particular message
    ///
    /// Once that message is fetched and yielded, the returned [`Stream`] will yield only
    /// descendants of that message.
    ///
    ///  See [example in `Messages` docs](struct.Messages.html#filter-the-messages-of-a-particular-branch)
    /// for more details.
    pub fn filter_branch<F>(
        self,
        predicate: impl FnMut(&UnwrappedMessage) -> F + 'a,
    ) -> impl Stream<Item = Result<UnwrappedMessage>> + 'a
    where
        F: Future<Output = Result<bool>> + 'a,
    {
        self.try_skip_while(predicate)
            .scan(None, |branch_last_link, msg| {
                future::ready(Some(msg.map(|msg| {
                    let branch_last_link = branch_last_link.get_or_insert(msg.prev_link);
                    if msg.prev_link == *branch_last_link {
                        *branch_last_link = msg.link;
                        Some(msg)
                    } else {
                        None
                    }
                })))
            })
            .try_filter_map(future::ok)
    }
}

impl<'a, Trans> From<&'a mut User<Trans>> for Messages<'a, Trans>
where
    Trans: Transport,
{
    fn from(user: &'a mut User<Trans>) -> Self {
        Self::new(user)
    }
}

impl<'a, Trans> Stream for Messages<'a, Trans>
where
    Trans: Transport,
{
    type Item = Result<UnwrappedMessage>;

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

    use std::{
        cell::RefCell,
        rc::Rc,
    };

    use crate::{api::tangle::BucketTransport, Address, User};
    use iota_streams_core::Result;

    type Transport = Rc<RefCell<BucketTransport>>;

    #[tokio::test]
    async fn messages_can_be_linked_to_sequence_messages() -> Result<()> {
        let p = Default::default();
        let (mut author, mut subscriber, announcement_link, transport) = author_subscriber_fixture().await?;

        let (keyload_link, _) = author.send_keyload_for_everyone(&announcement_link).await?;
        let (packet_link, _) = author.send_signed_packet(&keyload_link, &p, &p).await?;
        let (_, seq_link) = author.send_signed_packet(&packet_link, &p, &p).await?;

        subscriber.sync_state().await?;

        // This packet has to wait in the `Messages::msg_queue` until `seq_link` is processed
        subscriber
            .send_signed_packet(&seq_link.expect("sequence link should be Some(link)"), &p, &p)
            .await?;

        // Subscriber::reset_state() cannot be used, see https://github.com/iotaledger/streams/issues/161
        let mut subscriber = User::new("subscriber", transport).await;
        subscriber.receive_announcement(&announcement_link).await?;
        let n_msgs = subscriber.sync_state().await?;
        assert_eq!(n_msgs, 4); // keyload, 2 signed packets from author, and last signed-packet from herself
        Ok(())
    }

    #[tokio::test]
    async fn sequence_messages_awake_pending_messages_link_to_them_even_if_the_referenced_messages_are_unreadable(
    ) -> Result<()> {
        let p = Default::default();
        let (mut author, mut subscriber1, announcement_link, transport) = author_subscriber_fixture().await?;

        let (keyload_link, _) = author.send_keyload_for_everyone(&announcement_link).await?;
        subscriber1.sync_state().await?;
        let (packet_link, _) = subscriber1.send_signed_packet(&keyload_link, &p, &p).await?;
        // This packet will never be readable by subscriber2. However, the sequence is
        let (_, seq_link) = subscriber1.send_signed_packet(&packet_link, &p, &p).await?;

        let mut subscriber2 =
            subscriber_fixture("subscriber2", &mut author, &announcement_link, transport.clone()).await?;

        author.sync_state().await?;
        // This keyload link to announcement is necessary (for now) to "introduce" both subscribers
        // otherwise subscriber2 isn't aware of subscriber1 and will never walk through the sequence messages
        //  of subscriber1 to reach keyload2
        author.send_keyload_for_everyone(&announcement_link).await?;

        // This packet has to wait in the `Messages::msg_queue` until `seq_link` is processed
        let (keyload2_link, _) = author
            .send_keyload_for_everyone(&seq_link.expect("sequence link should be Some(link)"))
            .await?;

        subscriber1.sync_state().await?;
        subscriber1.send_signed_packet(&keyload2_link, &p, &p).await?;

        let n_msgs = subscriber2.sync_state().await?;
        assert_eq!(n_msgs, 4); // first announcement, announcement keyload, keyload2 and last signed packet
        Ok(())
    }

    /// Prepare a simple scenario with an author, a subscriber, a channel announcement and a bucket transport
    async fn author_subscriber_fixture() -> Result<(User<Transport>, User<Transport>, Address, Transport)> {
        let transport = Rc::new(RefCell::new(BucketTransport::new()));
        let mut author = User::new("author", transport.clone()).await;
        let announcement_link = author.send_announce().await?;
        let subscriber = subscriber_fixture("subscriber", &mut author, &announcement_link, transport.clone()).await?;
        Ok((author, subscriber, announcement_link, transport))
    }

    async fn subscriber_fixture(
        seed: &str,
        author: &mut User<Transport>,
        announcement_link: &Address,
        transport: Transport,
    ) -> Result<User<Transport>> {
        let mut subscriber = User::new(seed, transport).await;
        subscriber.receive_announcement(announcement_link).await?;
        let subscription = subscriber.send_subscribe(announcement_link).await?;
        author.receive_subscribe(&subscription).await?;
        Ok(subscriber)
    }
}
