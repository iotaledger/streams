pub mod command;
pub mod io;
pub mod types;

pub type Result<T> = std::result::Result<T, failure::Error>;
