<h1 align="center">
  <br>
  <a href="https://wiki.iota.org/streams/welcome"><img src="streams.png"></a>
</h1>

<h2 align="center">A cryptographic framework for building secure messaging protocols</h2>

<p align="center">
    <a href="https://wiki.iota.org/streams/welcome" style="text-decoration:none;">
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

IOTA Streams is a **work-in-progress** framework for building cryptographic messaging protocols. Streams ships with a built-in protocol called Channels for sending authenticated messages between two or more parties on the Tangle.

As a framework, Streams allows developers to build protocols for their specific needs.

This process will be documented as the development progresses. However, since this crate is in an alpha stage of development it is still likely to change.

At the moment, IOTA Streams includes the following crates:
* [API layer](streams/README.md) featuring common Application definitions.
* [Definition layer](lets/README.md) featuring Streams message definitions.
* [DDML](iota-streams-ddml/README.md) featuring data definition and manipulation language for protocol messages;

## Prerequisites
To use IOTA Streams, you need the following:
- [Rust](https://www.rust-lang.org/tools/install)
- (Optional) An IDE that supports Rust autocompletion. We recommend [Visual Studio Code](https://code.visualstudio.com/Download) with the [rust-analyzer](https://marketplace.visualstudio.com/items?itemName=matklad.rust-analyzer) extension

We also recommend updating Rust to the [latest stable version](https://github.com/rust-lang/rustup.rs#keeping-rust-up-to-date):

```bash
rustup update stable
```


## Installation

To use the library in your crate you need to add it as a dependency in the `Cargo.toml` file.

Because the library is not on [crates.io](https://crates.io/), you need to use the Git repository either remotely or locally.

`no_std` is currently supported. However cargo nightly must be used to build with `no_std` feature.

## Getting started

If you don't have a rust project setup yet you can create one by running,

    cargo new my-library

**Remote**
Add the following to your `Cargo.toml` file:

```bash
[dependencies]
anyhow = { version = "1.0", default-features = false }
streams = { git = "https://github.com/iotaledger/streams", branch = "main" }
```

**Local**

1. Clone this repository

    ```bash
    git clone https://github.com/iotaledger/streams
    ```

2. Add the following to your `Cargo.toml` file:

    ```bash
    [dependencies]
    streams = { version = "2.0.0", path = "../streams" }
    ```

## Getting started

After you've [installed the library](#installation), you can use it in your own Cargo project.

For example, you may want to use Streams to create a new author and send a message like so:

```rust
use streams::{
    transport::utangle::Client,
    id::Ed25519, User,
};

fn main() {
    let node = "http://localhost:14265";
    let transport: Client = Client::new(node);

    let mut author = User::builder()
        .with_transport(transport)
        .with_identity(Ed25519::from_seed("AUTHORSSEED"))
        .build();
    
    let base_branch = "BASE_BRANCH";
    let _announcement = author.create_stream(base_branch).await?;

    let payload = b"PUBLICPAYLOAD";
    // Create and send public message with payload (unencrypted)
    let message = author.message().public().with_payload(*payload).send().await?;
    // You can look this index up on a explorer
    println!("message index: {}", hex::encode(message.address().to_msg_index()));
}
```

 For a more detailed guide, go to our [documentation portal](https://wiki.iota.org/streams/welcome).

## API reference

To generate the API reference and display it in a web browser, do the following:

```bash
cargo doc --open
```

## Examples

We have an example in the [`examples` directory](streams/examples/full-example/main.rs), which you can use as a reference when developing your own protocols with IOTA Streams.

## Supporting the project

Please see our [contribution guidelines](CONTRIBUTING.md) for all the ways in which you can contribute.

### Running tests

We use code comments to write tests. You can run all tests by doing the following from the `streams` directory:

```
cargo test --all
```

### Updating documentation

If you want to improve the code comments, please do so according to the guidelines in [RFC 1574](https://github.com/rust-lang/rfcs/blob/master/text/1574-more-api-documentation-conventions.md#appendix-a-full-conventions-text).

## Joining the discussion

If you want to get involved in discussions about this technology, or you're looking for support, go to the #streams-discussion channel on [Discord](https://discord.iota.org/).
