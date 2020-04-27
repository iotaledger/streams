<h1 align="center">
  <br>
  <a href="https://docs.iota.org/docs/iota-streams/0.1/introduction/overview.md"><img src="streams.png"></a>
</h1>

<h2 align="center">A cryptographic framework for building secure messaging applications</h2>

<p align="center">
    <a href="https://docs.iota.org/docs/iota-streams/0.1/introduction/overview.md" style="text-decoration:none;">
    <img src="https://img.shields.io/badge/Documentation%20portal-blue.svg?style=for-the-badge"
         alt="Developer documentation portal">
      </p>
<p align="center">
	<a href="https://discord.iota.org/" style="text-decoration:none;"><img src="https://img.shields.io/badge/Discord-9cf.svg?logo=discord" alt="Discord"></a>
    <a href="https://iota.stackexchange.com/" style="text-decoration:none;"><img src="https://img.shields.io/badge/StackExchange-9cf.svg?logo=stackexchange" alt="StackExchange"></a>
    <a href="https://raw.githubusercontent.com/iotaledger/streams/master/LICENSE" style="text-decoration:none;"><img src="https://img.shields.io/badge/license-Apache%202.0-green.svg" alt="Apache 2.0 license"></a>
</p>
      
<p align="center">
  <a href="#about">About</a> ◈
  <a href="#prerequisites">Prerequisites</a> ◈
  <a href="#installation">Installation</a> ◈
  <a href="#getting-started">Getting started</a> ◈
  <a href="#api-reference">API reference</a> ◈
  <a href="#examples">Examples</a> ◈
  <a href="#supporting-the-project">Supporting the project</a> ◈
  <a href="#joining-the-discussion">Joining the discussion</a> 
</p>

---

## About

IOTA Streams is a **work-in-progress** framework for cryptographic messaging protocols called Applications. Streams ships with a built-in application called Channels for sending authenticated messages between two or more parties on the Tangle.

As a cryptographic framework, Streams allows developers to build Applications for their specific needs.

This process will be documented as the development progresses. However, since this crate is in an alpha stage of development it is still likely to change.

At the moment, IOTA Streams includes the following crates:

- `iota_streams_app_channels`: An API for using the built-in Channels application
- `iota_streams_app`: The `message` and `transport` modules for creating your own Streams applications
- `iota_streams_core`: Modules for the core cryptographic features used by Streams, including ternary to binary conversions
- `iota_streams_core_keccak`: Modules for using sponge constructions with KeccakF1600B and KeccakF1600T permutations
- `iota_streams_core_merkletree`: A module for working with traversable Merkle trees
- `iota_streams_core_mss`: Modules for validating Merkle tree signatures and generating private keys, public keys and signatures with the Winternitz one-time signature scheme
- `iota_streams_core_ntru`:  A module for working with NTRU key pairs
- `iota_streams_protobuf3`: Modules for working with the IOTA trinary data description language called Protobuf3, in which all Streams messages are encoded

## Prerequisites

To use IOTA Streams, you need the following:
- [Rust](https://www.rust-lang.org/tools/install)
- (Optional) An IDE that supports Rust autocompletion. We recommend [Visual Studio Code](https://code.visualstudio.com/Download) with the [rust-analyzer](https://marketplace.visualstudio.com/items?itemName=matklad.rust-analyzer) extension

We also recommend updating Rust to the [latest stable version](https://github.com/rust-lang/rustup.rs#keeping-rust-up-to-date):

```bash
rustup update stable
```

`no_std` is not currently supported.

## Installation

To use the library in your crate you need to add it as a dependancy in the `Cargo.toml` file.

Because the library is not on [crates.io](https://crates.io/), you need to use the Git repository either remotely or locally.

**Remote**

Add the following to your `Cargo.toml` file:

```bash
[dependencies]
iota-streams = { git = "https://github.com/iotaledger/streams" }
```

**Local**

1. Clone this repository

    ```bash
    git clone https://github.com/iotaledger/streams
    ```

2. Add the following to your `Cargo.toml` file:

    ```bash
    [dependencies]
    iota-streams = { version = "0.1", path = "../streams" }
    ```

## Getting started

After you've [installed the library](#installation), you can use it in your own Cargo project.

For example, you may want to use the Channels application to create a new channel like so:

```rust
use iota_streams::app_channels::api::tangle::{Author, Transport};
use iota_lib_rs::prelude::iota_client;
use iota_streams::app::transport::tangle::client::SendTrytesOptions;

fn main() {
    let author = Author::new("AUTHORSSEED", 3, false);

    // Create an `Announce` message to start the channel
    let announcement = author.announce()?;

    // Print the information that needs to be sent to subscribers before they can read the message
    println!("Message identifier: {}", announcement.link.msgid.to_string());

    // Connect to an IOTA node
    let mut client = iota_client::Client::new("https://nodes.iota.org:443");

    // Change the default settings to use a lower minimum weight magnitude for the Devnet
    let mut send_opt = SendTrytesOptions::default();

    // Convert the message to a bundle and send it to a node
    client.send_message_with_options(&announcement, send_opt)?;
    println!("Sent Announce message");
}
```

 For a more detailed guide, go to our [documentation portal](https://docs.iota.org/docs/channels/0.1/introduction/get-started.md).

## API reference

To generate the API reference and display it in a web browser, do the following:

```bash
cargo doc --open
```

## Examples

We have a list of test cases in the [`examples` directory](iota-streams-app-channels/examples) that you can use as a reference when developing applications with IOTA Streams.

## Supporting the project

If this library has been useful to you and you feel like contributing, consider posting a [bug report](https://github.com/iotaledger/streams/issues/new), [feature request](https://github.com/iotaledger/streams/issues/new) or a [pull request](https://github.com/iotaledger/streams/pulls/).

### Running tests

We use code comments to write tests. You can run all tests by doing the following from the `streams` directory:

```
cargo test --all
```

### Updating documentation

Please update the documention when needed by editing the code comments according to the guidelines in [RFC 1574](https://github.com/rust-lang/rfcs/blob/master/text/1574-more-api-documentation-conventions.md#appendix-a-full-conventions-text).

## Joining the discussion

If you want to get involved in the community, need help with getting set up, have any issues related with the library or just want to discuss IOTA, Distributed Registry Technology (DRT) and IoT with other people, feel free to join our [Discord](https://discord.iota.org/).
