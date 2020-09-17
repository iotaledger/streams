use iota::client as iota_client;
use iota_streams_app_channels::api::tangle::test::example;

fn main() {
    iota_client::Client::add_node("https://nodes.devnet.iota.org:443").unwrap();
    let mut transport = iota_client::Client::get();
    assert!(dbg!(example(&mut transport)).is_ok());
}
