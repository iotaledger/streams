pub mod pk_store;
pub mod psk_store;

/// We would need an array import in prelude, and using IntoIter with size specifying...
/// type_complexity to be detemined in future issue
#[allow(clippy::ptr_arg, clippy::type_complexity)]
pub mod user;

/// Tangle-specific Channel API.
#[cfg(all(feature = "tangle"))]
pub mod tangle;

#[derive(Clone)]
pub enum ImplementationType {
    SingleBranch,
    MultiBranch,
    SingleDepth
}
