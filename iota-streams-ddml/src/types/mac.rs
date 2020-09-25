/// The value wrapped in Mac is just the size of message authentication tag (MAC) in trits.
/// The actual trits are not important. The requested amount of trits is squeezed
/// from Spongos and encoded in the trinary stream during Wrap operation.
/// During Unwrap operation the requested amount of trits is squeezed from Spongos
/// and compared to the trits encoded in the trinary stream.
#[derive(PartialEq, Eq, Copy, Clone, Debug)]
pub struct Mac(pub usize);
