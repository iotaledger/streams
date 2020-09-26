use iota::client as iota_client;
use iota_streams_app_channels::api::tangle::test::example;
use iota_streams_app::transport::tangle::client::{SendTrytesOptions, RecvOptions};

fn main() {
    iota_client::Client::add_node("https://nodes.devnet.iota.org:443").unwrap();

    let mut send_opt = SendTrytesOptions::default();
    send_opt.min_weight_magnitude = 14;

    let transport = iota_client::Client::get();
    assert!(dbg!(example(transport, RecvOptions{flags: 0}, send_opt)).is_ok());
}
