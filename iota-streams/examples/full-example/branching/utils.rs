// Rust

// 3rd-party
use textwrap::indent;

// IOTA

// Streams
use iota_streams::{
    Address,
    SendResponse,
    TransportMessage,
    User,
};

// Local

pub fn print_user<T>(user_name: &str, user: &User<T>) {
    println!("  {}:\n{}", user_name, indent(&format!("{:?}", user), "\t"));
}

pub fn print_send_result(msg: &SendResponse<Address, TransportMessage>) {
    println!(
        "  msg => <{}> [{}]",
        msg.address().relative(),
        hex::encode(msg.address().to_msg_index())
    );
}
