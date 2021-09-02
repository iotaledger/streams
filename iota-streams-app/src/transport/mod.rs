use iota_streams_core::{
    async_trait,
    prelude::{
        Arc,
        Box,
        Mutex,
        Rc,
        Vec,
    },
    Result,
};

use core::{
    cell::RefCell,
    marker::{
        Send,
        Sync,
    },
};

#[async_trait(?Send)]
pub trait TransportDetails<Link> {
    type Details;
    async fn get_link_details(&mut self, link: &Link) -> Result<Self::Details>;
}

#[async_trait(?Send)]
pub trait TransportOptions {
    type SendOptions;
    async fn get_send_options(&self) -> Self::SendOptions;
    async fn set_send_options(&mut self, opt: Self::SendOptions);

    type RecvOptions;
    async fn get_recv_options(&self) -> Self::RecvOptions;
    async fn set_recv_options(&mut self, opt: Self::RecvOptions);
}

/// Network transport abstraction.
/// Parametrized by the type of message links.
/// Message link is used to identify/locate a message (eg. like URL for HTTP).
#[async_trait(?Send)]
pub trait Transport<Link, Msg>: TransportOptions + TransportDetails<Link> {
    /// Send a message with default options.
    async fn send_message(&mut self, msg: &Msg) -> Result<()>;

    /// Receive messages with default options.
    async fn recv_messages(&mut self, link: &Link) -> Result<Vec<Msg>>;

    /// Receive a message with default options.
    async fn recv_message(&mut self, link: &Link) -> Result<Msg>;
}

pub type SharedTransport<T> = Rc<RefCell<T>>;

pub fn new_shared_transport<T>(tsp: T) -> Rc<RefCell<T>> {
    Rc::new(RefCell::new(tsp))
}

#[async_trait(?Send)]
impl<Tsp: TransportOptions> TransportOptions for Arc<Mutex<Tsp>> {
    type SendOptions = <Tsp as TransportOptions>::SendOptions;
    async fn get_send_options(&self) -> Self::SendOptions {
        (&*self).lock().get_send_options().await
    }
    async fn set_send_options(&mut self, opt: Self::SendOptions) {
        (&*self).lock().set_send_options(opt).await
    }

    type RecvOptions = <Tsp as TransportOptions>::RecvOptions;
    async fn get_recv_options(&self) -> Self::RecvOptions {
        (&*self).lock().get_recv_options().await
    }
    async fn set_recv_options(&mut self, opt: Self::RecvOptions) {
        (&*self).lock().set_recv_options(opt).await
    }
}

#[async_trait(?Send)]
impl<Link, Tsp: TransportDetails<Link>> TransportDetails<Link> for Arc<Mutex<Tsp>> {
    type Details = <Tsp as TransportDetails<Link>>::Details;
    async fn get_link_details(&mut self, link: &Link) -> Result<Self::Details> {
        (&*self).lock().get_link_details(link).await
    }
}

#[async_trait(?Send)]
impl<Link, Msg, Tsp: Transport<Link, Msg>> Transport<Link, Msg> for Arc<Mutex<Tsp>> {
    // Send a message.
    async fn send_message(&mut self, msg: &Msg) -> Result<()> {
        (&*self).lock().send_message(msg).await
    }

    // Receive messages with default options.
    async fn recv_messages(&mut self, link: &Link) -> Result<Vec<Msg>> {
        (&*self).lock().recv_messages(link).await
    }

    // Receive a message with default options.
    async fn recv_message(&mut self, link: &Link) -> Result<Msg> {
        (&*self).lock().recv_message(link).await
    }
}

pub type MultiThreadTransport<T> = Arc<Mutex<T>>;

pub fn new_multi_thread_transport<T>(tsp: T) -> Arc<Mutex<T>> {
    Arc::new(Mutex::new(tsp))
}

mod bucket;
pub use bucket::BucketTransport;
use iota_streams_core::try_or;

#[cfg(feature = "tangle")]
pub mod tangle;
