use iota_streams_core::{
    async_trait,
    prelude::{Box, Rc, RefCell, Vec},
    Result,
};

#[async_trait(?Send)]
pub trait TransportDetails<Link> {
    type Details;
    async fn get_link_details(&mut self, link: &Link) -> Result<Self::Details>;
}

pub trait TransportOptions {
    type SendOptions;
    fn get_send_options(&self) -> Self::SendOptions;
    fn set_send_options(&mut self, opt: Self::SendOptions);

    type RecvOptions;
    fn get_recv_options(&self) -> Self::RecvOptions;
    fn set_recv_options(&mut self, opt: Self::RecvOptions);
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

impl<Tsp: TransportOptions> TransportOptions for Rc<RefCell<Tsp>> {
    type SendOptions = <Tsp as TransportOptions>::SendOptions;
    fn get_send_options(&self) -> Self::SendOptions {
        self.borrow_mut().get_send_options()
    }
    fn set_send_options(&mut self, opt: Self::SendOptions) {
        self.borrow_mut().set_send_options(opt)
    }

    type RecvOptions = <Tsp as TransportOptions>::RecvOptions;
    fn get_recv_options(&self) -> Self::RecvOptions {
        self.borrow_mut().get_recv_options()
    }
    fn set_recv_options(&mut self, opt: Self::RecvOptions) {
        self.borrow_mut().set_recv_options(opt)
    }
}

#[async_trait(?Send)]
impl<Link, Tsp: TransportDetails<Link>> TransportDetails<Link> for Rc<RefCell<Tsp>> {
    type Details = <Tsp as TransportDetails<Link>>::Details;
    async fn get_link_details(&mut self, link: &Link) -> Result<Self::Details> {
        self.borrow_mut().get_link_details(link).await
    }
}

#[async_trait(?Send)]
impl<Link, Msg, Tsp: Transport<Link, Msg>> Transport<Link, Msg> for Rc<RefCell<Tsp>> {
    // Send a message.
    async fn send_message(&mut self, msg: &Msg) -> Result<()> {
        self.borrow_mut().send_message(msg).await
    }

    // Receive messages with default options.
    async fn recv_messages(&mut self, link: &Link) -> Result<Vec<Msg>> {
        self.borrow_mut().recv_messages(link).await
    }

    // Receive a message with default options.
    async fn recv_message(&mut self, link: &Link) -> Result<Msg> {
        self.borrow_mut().recv_message(link).await
    }
}

#[cfg(any(feature = "sync-spin", feature = "sync-parking-lot"))]
mod sync {
    use super::{Transport, TransportDetails, TransportOptions};
    use iota_streams_core::{
        async_trait,
        prelude::{Arc, Box, Mutex, Vec},
        Result,
    };

    impl<Tsp: TransportOptions> TransportOptions for Arc<Mutex<Tsp>> {
        type SendOptions = <Tsp as TransportOptions>::SendOptions;
        fn get_send_options(&self) -> Self::SendOptions {
            self.lock().get_send_options()
        }
        fn set_send_options(&mut self, opt: Self::SendOptions) {
            self.lock().set_send_options(opt)
        }

        type RecvOptions = <Tsp as TransportOptions>::RecvOptions;
        fn get_recv_options(&self) -> Self::RecvOptions {
            self.lock().get_recv_options()
        }
        fn set_recv_options(&mut self, opt: Self::RecvOptions) {
            self.lock().set_recv_options(opt)
        }
    }

    #[async_trait(?Send)]
    impl<Link, Tsp: TransportDetails<Link>> TransportDetails<Link> for Arc<Mutex<Tsp>> {
        type Details = <Tsp as TransportDetails<Link>>::Details;
        async fn get_link_details(&mut self, link: &Link) -> Result<Self::Details> {
            self.lock().get_link_details(link).await
        }
    }

    #[async_trait(?Send)]
    impl<Link, Msg, Tsp: Transport<Link, Msg>> Transport<Link, Msg> for Arc<Mutex<Tsp>> {
        // Send a message.
        async fn send_message(&mut self, msg: &Msg) -> Result<()> {
            self.lock().send_message(msg).await
        }

        // Receive messages with default options.
        async fn recv_messages(&mut self, link: &Link) -> Result<Vec<Msg>> {
            self.lock().recv_messages(link).await
        }

        // Receive a message with default options.
        async fn recv_message(&mut self, link: &Link) -> Result<Msg> {
            self.lock().recv_message(link).await
        }
    }
}

mod bucket;
pub use bucket::BucketTransport;
use iota_streams_core::try_or;

#[cfg(feature = "tangle")]
pub mod tangle;
