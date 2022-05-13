use LETS::address::Address;

#[derive(Clone, Copy, PartialEq, Eq, Debug, Hash, Default)]
pub struct SendResponse<TSR> {
    address: Address,
    transport_response: TSR,
}

impl<TSR> SendResponse<TSR> {
    pub(crate) fn new(address: Address, transport_response: TSR) -> Self {
        Self {
            address,
            transport_response,
        }
    }

    pub fn address(&self) -> Address {
        self.address
    }

    pub fn response(&self) -> &TSR {
        &self.transport_response
    }

    pub fn into_response(self) -> TSR {
        self.transport_response
    }
}
