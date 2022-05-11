// Rust

// 3rd-party

// Local

pub trait Link {
    /// Type of "base" links. For http it's domain name.
    type Base;
    /// Type of "relative" links. For http it's URL path.
    type Relative;

    /// Get base part of the link.
    fn base(&self) -> &Self::Base;

    fn into_base(self) -> Self::Base;

    /// Get relative part of the link.
    fn relative(&self) -> &Self::Relative;

    fn into_relative(self) -> Self::Relative;

    /// Construct absolute link from base and relative parts.
    fn from_parts(base: Self::Base, rel: Self::Relative) -> Self;
}

pub trait LinkGenerator<'a, Address> {
    type Data;

    fn gen(&mut self, data: Self::Data) -> Address;
}

pub(crate) trait Linked<Address> {
    fn linked_msg(&self) -> &Address;
}

pub(crate) trait Addressable<Address> {
    fn address(&self) -> &Address;
}

pub(crate) trait Indexable<Index> {
    fn index(&self) -> Index;
}

pub(crate) trait Index {
    fn to_index<T>(&self) -> T
    where
        T: AsRef<[u8]>;
}
