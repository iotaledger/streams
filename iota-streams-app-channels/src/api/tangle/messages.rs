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
    identifier::Identifier,
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
/// created from any type implementing [`IntoMessages`], calling its [`IntoMessages::messages()`] method (both
/// [`Author`](struct.Author.html) and [`Subscriber`](struct.Subscriber.html) implement it). The main method is
/// [`Messages::next()`], which returns the next message in the channel that is readable by the user.
///
/// This type implements [`futures::Stream`] and [`futures::TryStream`], therefore it can be used with all the adapters
/// provided by [`futures::StreamExt`] and [`futures::TryStreamExt`]:
///
/// ## Iterate over the pending messages
/// ```
/// use iota_streams_app_channels::{
///     api::tangle::futures::TryStreamExt,
///     Address,
///     Author,
///     Bytes,
///     ChannelType,
///     MessageContent,
///     Subscriber,
///     Tangle,
///     UnwrappedMessage,
/// };
///
/// #
/// # use std::cell::RefCell;
/// # use std::rc::Rc;
/// # use iota_streams_app_channels::api::tangle::BucketTransport;
/// # use iota_streams_core::Result;
/// #
/// # fn main() -> Result<()> {
/// # smol::block_on(async {
/// # let test_transport = Rc::new(RefCell::new(BucketTransport::new()));
/// #
/// let author_seed = "cryptographically-secure-random-author-seed";
/// let author_transport = Tangle::new_from_url("https://chrysalis-nodes.iota.org");
/// #
/// # let author_transport = test_transport.clone();
/// #
/// let mut author = Author::new(author_seed, ChannelType::SingleBranch, author_transport);
///
/// let subscriber_seed = "cryptographically-secure-random-subscriber-seed";
/// let subscriber_transport = Tangle::new_from_url("https://chrysalis-nodes.iota.org");
/// #
/// # let subscriber_transport = test_transport.clone();
/// #
/// let mut subscriber = Subscriber::new(subscriber_seed, subscriber_transport);
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
/// # })
/// # }
/// ```
///
/// ## Collect all the pending messages into a Vector (or any other collection type)
/// ```
/// use iota_streams_app_channels::{
///     api::tangle::futures::TryStreamExt,
///     Address,
///     Author,
///     ChannelType,
///     MessageContent,
///     Subscriber,
///     Tangle,
///     UnwrappedMessage,
/// };
///
/// #
/// # use std::cell::RefCell;
/// # use std::rc::Rc;
/// # use iota_streams_app_channels::api::tangle::BucketTransport;
/// # use iota_streams_core::Result;
/// #
/// # fn main() -> Result<()> {
/// #  smol::block_on(async {
/// # let test_transport = Rc::new(RefCell::new(BucketTransport::new()));
/// #
/// let author_seed = "cryptographically-secure-random-author-seed";
/// let author_transport = Tangle::new_from_url("https://chrysalis-nodes.iota.org");
/// #
/// # let author_transport = test_transport.clone();
/// #
/// let mut author = Author::new(author_seed, ChannelType::SingleBranch, author_transport);
///
/// let subscriber_seed = "cryptographically-secure-random-subscriber-seed";
/// let subscriber_transport = Tangle::new_from_url("https://chrysalis-nodes.iota.org");
/// #
/// # let subscriber_transport = test_transport.clone();
/// #
/// let mut subscriber = Subscriber::new(subscriber_seed, subscriber_transport);
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
///             MessageContent::new_signed_packet(
///                 author.get_public_key().clone(),
///                 b"public payload",
///                 b"masked payload"
///             )
///         ),
///         UnwrappedMessage::new(
///             second_packet_link,
///             first_packet_link,
///             MessageContent::new_signed_packet(
///                 author.get_public_key().clone(),
///                 b"another public payload",
///                 b"another masked payload"
///             )
///         ),
///     ]
/// );
/// #
/// # Ok(())
/// # })
/// # }
/// ```
///
/// ## Iterate over the channel messages indefinitely
/// ```
/// use iota_streams_app_channels::{
///     api::tangle::futures::TryStreamExt,
///     Address,
///     Author,
///     Bytes,
///     ChannelType,
///     MessageContent,
///     Subscriber,
///     Tangle,
///     UnwrappedMessage,
/// };
/// # use iota_streams_app_channels::api::tangle::BucketTransport;
/// # use iota_streams_core::{prelude::{Rc, RefCell}, Result};
///
/// # fn main() -> Result<()> {
/// # smol::block_on(async {
/// # let test_transport = Rc::new(RefCell::new(BucketTransport::new()));
/// #
/// // Process 1...
/// let author_seed = "cryptographically-secure-random-author-seed";
/// let author_transport = Tangle::new_from_url("https://chrysalis-nodes.iota.org");
/// #
/// # let author_transport = test_transport.clone();
/// #
/// let mut author = Author::new(author_seed, ChannelType::SingleBranch, author_transport);
/// let announcement_link = author.send_announce().await?;
/// let shareable_announcement_link = announcement_link.to_string();
///
/// // Process 2...
/// let subscriber_seed = "cryptographically-secure-random-subscriber-seed";
/// let subscriber_transport = Tangle::new_from_url("https://chrysalis-nodes.iota.org");
/// #
/// # let subscriber_transport = test_transport.clone();
/// #
/// let mut subscriber = Subscriber::new(subscriber_seed, subscriber_transport);
/// let announcement_link = shareable_announcement_link.parse().expect("parsing announcement link");
/// subscriber.receive_announcement(&announcement_link).await?;
/// let subscription_link = subscriber.send_subscribe(&announcement_link).await?;
/// let shareable_subscription_link = subscription_link.to_string();
/// #
/// # let subscriber_process = async move {
/// #
/// # let mut n = 0;
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
///
/// // Process 1...
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
/// # })
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
///     Author,
///     Bytes,
///     ChannelType,
///     MessageContent,
///     Subscriber,
///     Tangle,
///     UnwrappedMessage,
/// };
///
/// #
/// # use std::cell::RefCell;
/// # use std::rc::Rc;
/// # use iota_streams_app_channels::api::tangle::BucketTransport;
/// # use iota_streams_core::Result;
/// #
/// # fn main() -> Result<()> {
/// # smol::block_on(async {
/// # let test_transport = Rc::new(RefCell::new(BucketTransport::new()));
/// #
/// let author_seed = "cryptographically-secure-random-author-seed";
/// let author_transport = Tangle::new_from_url("https://chrysalis-nodes.iota.org");
/// #
/// # let author_transport = test_transport.clone();
/// #
/// let mut author = Author::new(author_seed, ChannelType::MultiBranch, author_transport);
///
/// let subscriber_seed = "cryptographically-secure-random-subscriber-seed";
/// let subscriber_transport = Tangle::new_from_url("https://chrysalis-nodes.iota.org");
/// #
/// # let subscriber_transport = test_transport.clone();
/// #
/// let mut subscriber = Subscriber::new(subscriber_seed, subscriber_transport);
///
/// let announcement_link = author.send_announce().await?;
/// subscriber.receive_announcement(&announcement_link).await?;
/// let subscription_link = subscriber.send_subscribe(&announcement_link).await?;
/// author.receive_subscribe(&subscription_link).await?;
/// let (first_keyload_link, _sequence_link) = author.send_keyload_for_everyone(&announcement_link).await?;
/// let (tag_first_branch_link, _sequence_link) = author
///     .send_signed_packet(&first_keyload_link, &Bytes::new(), &b"branch 1".into())
///     .await?;
/// let (first_packet_first_branch_link, _sequence_link) = author
///     .send_signed_packet(
///         &tag_first_branch_link,
///         &Bytes::new(),
///         &b"masked payload in branch 1".into(),
///     )
///     .await?;
/// let (second_packet_first_branch_link, _sequence_link) = author
///     .send_signed_packet(
///         &first_packet_first_branch_link,
///         &Bytes::new(),
///         &b"another masked payload in branch 1".into(),
///     )
///     .await?;
///
/// let (second_keyload_link, sequence_link) = author.send_keyload_for_everyone(&announcement_link).await?;
/// let (tag_second_branch_link, _sequence_link) = author
///     .send_signed_packet(&second_keyload_link, &Bytes::new(), &b"branch 2".into())
///     .await?;
/// let (first_packet_second_branch_link, sequence_link) = author
///     .send_signed_packet(
///         &tag_second_branch_link,
///         &Bytes::new(),
///         &b"masked payload in branch 2".into(),
///     )
///     .await?;
/// let (second_packet_second_branch_link, sequence_link) = author
///     .send_signed_packet(
///         &first_packet_second_branch_link,
///         &Bytes::new(),
///         &b"another masked payload in branch 2".into(),
///     )
///     .await?;
///
/// let messages: Vec<UnwrappedMessage> = subscriber
///     .messages()
///     .try_skip_while(|msg| {
///         future::ok(
///             msg.body
///                 .masked_payload()
///                 .and_then(Bytes::as_str)
///                 .map(|payload| payload != "branch 2")
///                 .unwrap_or(true),
///         )
///     })
///     .scan(None, |branch_last_link, msg| {
///         future::ready(Some(msg.map(|msg| {
///             let branch_last_link = branch_last_link.get_or_insert(msg.prev_link);
///             if msg.prev_link == *branch_last_link {
///                 *branch_last_link = msg.link;
///                 Some(msg)
///             } else {
///                 None
///             }
///         })))
///     })
///     .try_filter_map(future::ok)
///     .skip(1) // skip tag message
///     .try_collect()
///     .await?;
/// assert_eq!(
///     messages,
///     vec![
///         UnwrappedMessage::new(
///             first_packet_second_branch_link,
///             tag_second_branch_link,
///             MessageContent::new_signed_packet(
///                 author.get_public_key().clone(),
///                 Bytes::new(),
///                 b"masked payload in branch 2"
///             )
///         ),
///         UnwrappedMessage::new(
///             second_packet_second_branch_link,
///             first_packet_second_branch_link,
///             MessageContent::new_signed_packet(
///                 author.get_public_key().clone(),
///                 Bytes::new(),
///                 b"another masked payload in branch 2"
///             )
///         ),
///     ]
/// );
///
/// // This particular case is conveniently abstracted away in the Messages::filter_branch():
/// subscriber.reset_state();
/// assert_eq!(
///     messages,
///     subscriber
///         .messages()
///         .filter_branch(|msg| future::ok(
///             msg.body
///                 .masked_payload()
///                 .and_then(Bytes::as_str)
///                 .map(|payload| payload != "branch 2")
///                 .unwrap_or(true)
///         ))
///         .skip(1)
///         .try_collect::<Vec<UnwrappedMessage>>()
///         .await?
/// );
/// # Ok(())
/// # })
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
            match self.user.handle_message(binary_msg, true).await {
                Ok(UnwrappedMessage {
                    body: MessageContent::Unreadable(unreadable_binary),
                    prev_link,
                    ..
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
                    self.next().await
                }
                Ok(readable_msg) => {
                    // Check if message has descendants pending to process and stage them for processing
                    if let Some(msgs) = self.msg_queue.remove(readable_msg.link()) {
                        self.stage.extend(msgs);
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
                    self.stage.push_back(msg.binary);
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
    /// ```
    /// use iota_streams_app_channels::{
    ///     api::tangle::futures::{
    ///         future,
    ///         StreamExt,
    ///         TryStreamExt,
    ///     },
    ///     Address,
    ///     Author,
    ///     Bytes,
    ///     ChannelType,
    ///     MessageContent,
    ///     Subscriber,
    ///     Tangle,
    ///     UnwrappedMessage,
    /// };
    ///
    /// #
    /// # use std::cell::RefCell;
    /// # use std::rc::Rc;
    /// # use iota_streams_app_channels::api::tangle::BucketTransport;
    /// # use iota_streams_core::Result;
    /// #
    /// # fn main() -> Result<()> {
    /// # smol::block_on(async {
    /// # let test_transport = Rc::new(RefCell::new(BucketTransport::new()));
    /// #
    /// let author_seed = "cryptographically-secure-random-author-seed";
    /// let author_transport = Tangle::new_from_url("https://chrysalis-nodes.iota.org");
    /// #
    /// # let author_transport = test_transport.clone();
    /// #
    /// let mut author = Author::new(author_seed, ChannelType::MultiBranch, author_transport);
    ///
    /// let subscriber_seed = "cryptographically-secure-random-subscriber-seed";
    /// let subscriber_transport = Tangle::new_from_url("https://chrysalis-nodes.iota.org");
    /// #
    /// # let subscriber_transport = test_transport.clone();
    /// #
    /// let mut subscriber = Subscriber::new(subscriber_seed, subscriber_transport);
    ///
    /// let announcement_link = author.send_announce().await?;
    /// subscriber.receive_announcement(&announcement_link).await?;
    /// let subscription_link = subscriber.send_subscribe(&announcement_link).await?;
    /// author.receive_subscribe(&subscription_link).await?;
    ///
    /// let (first_keyload_link, _sequence_link) = author.send_keyload_for_everyone(&announcement_link).await?;
    /// let (tag_first_branch_link, _sequence_link) = author
    ///     .send_signed_packet(&first_keyload_link, &Bytes::new(), &b"branch 1".into())
    ///     .await?;
    /// let (first_packet_first_branch_link, _sequence_link) = author
    ///     .send_signed_packet(
    ///         &tag_first_branch_link,
    ///         &Bytes::new(),
    ///         &b"masked payload in branch 1".into(),
    ///     )
    ///     .await?;
    ///
    /// let (second_keyload_link, sequence_link) = author.send_keyload_for_everyone(&announcement_link).await?;
    /// let (tag_second_branch_link, _sequence_link) = author
    ///     .send_signed_packet(&second_keyload_link, &Bytes::new(), &b"branch 2".into())
    ///     .await?;
    /// let (first_packet_second_branch_link, sequence_link) = author
    ///     .send_signed_packet(
    ///         &tag_second_branch_link,
    ///         &Bytes::new(),
    ///         &b"masked payload in branch 2".into(),
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
    ///     .try_collect()
    ///     .await?;
    ///
    /// assert_eq!(
    ///     messages,
    ///     vec![
    ///         UnwrappedMessage::new(
    ///             tag_second_branch_link,
    ///             second_keyload_link,
    ///             MessageContent::new_signed_packet(author.get_public_key().clone(), Bytes::new(), b"branch 2")
    ///         ),
    ///         UnwrappedMessage::new(
    ///             first_packet_second_branch_link,
    ///             tag_second_branch_link,
    ///             MessageContent::new_signed_packet(
    ///                 author.get_public_key().clone(),
    ///                 Bytes::new(),
    ///                 b"masked payload in branch 2"
    ///             )
    ///         ),
    ///     ]
    /// );
    /// # Ok(())
    /// # })
    /// # }
    /// ```
    ///  See [example in `Messages` docs](struct.Messages.html#filter-the-messages-of-a-particular-branch)
    /// for more details.
    pub fn filter_branch<F>(
        self,
        p: impl FnMut(&UnwrappedMessage) -> F + 'a,
    ) -> impl Stream<Item = Result<UnwrappedMessage>> + 'a
    where
        F: Future<Output = Result<bool>> + 'a,
    {
        self.try_skip_while(p)
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
