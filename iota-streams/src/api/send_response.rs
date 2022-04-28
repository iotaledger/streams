#[derive(Clone, Copy, PartialEq, Eq, Debug, Hash, Default)]
pub struct SendResponse<Address, TSR> {
    address: Address,
    transport_response: TSR,
}

impl<Address, TSR> SendResponse<Address, TSR> {
    pub(crate) fn new(address: Address, transport_response: TSR) -> Self {
        Self {
            address,
            transport_response,
        }
    }

    pub fn address(&self) -> &Address {
        &self.address
    }

    pub fn into_address(self) -> Address {
        self.address
    }

    pub fn to_address(&self) -> Address where Address: Copy {
        self.address
    }

    pub fn response(&self) -> &TSR {
        &self.transport_response
    }

    pub fn into_response(self) -> TSR {
        self.transport_response
    }
}
