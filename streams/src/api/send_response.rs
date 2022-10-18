use lets::address::Address;

/// A wrapper for a sent message
#[derive(Clone, Copy, PartialEq, Eq, Debug, Hash, Default)]
pub struct SendResponse<TSR> {
    /// [`Address`] of the message that was sent
    address: Address,
    /// The Transport Send Response
    transport_response: TSR,
}

impl<TSR> SendResponse<TSR> {
    /// Creates a new [`SendResponse`]
    ///
    /// # Arguments
    /// * `address`: The [`Address`] of the message that was sent
    /// * `transport_response`: The transport send response
    pub(crate) fn new(address: Address, transport_response: TSR) -> Self {
        Self {
            address,
            transport_response,
        }
    }

    /// Returns the [`Address`] of the message
    pub fn address(&self) -> Address {
        self.address
    }

    /// Returns a reference to the transport send response of the message
    pub fn response(&self) -> &TSR {
        &self.transport_response
    }

    /// Consumes the [`SendResponse`], returning the transport send response of the message
    pub fn into_response(self) -> TSR {
        self.transport_response
    }
}
