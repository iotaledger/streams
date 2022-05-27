// Rust

// 3rd-party
use textwrap::indent;

// IOTA

// Streams
use streams::{SendResponse, TransportMessage, User};

// Local

pub fn print_user<T>(user_name: &str, user: &User<T>) {
    println!("  {}:\n{}", user_name, indent(&format!("{:?}", user), "\t"));
}

pub fn print_send_result(msg: &SendResponse<TransportMessage>) {
    println!(
        "  msg => <{}> [{}]",
        msg.address().msg(),
        hex::encode(msg.address().to_msg_index())
    );
}
