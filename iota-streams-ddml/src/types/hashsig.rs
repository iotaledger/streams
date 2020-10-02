/// Mssig command modifier, it instructs Context to squeeze external hash value, commit
/// spongos state, sign squeezed hash and encode (without absorbing!) signature.
#[derive(PartialEq, Eq, Copy, Clone, Debug)]
pub struct HashSig;
