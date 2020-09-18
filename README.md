# IOTA Streams

This is the **WIP** Rust IOTA Streams library, it consists of the following components:
* [Channels Application](iota-streams-app-channels/README.md) featuring Channels Application.
* [Core layers](iota-streams-core/README.md) featuring spongos automaton for sponge-based authenticated encryption, pre-shared keys, pseudo-random generator;
* [Keccak for core layers](iota-streams-core-keccak/README.md) featuring Keccak-F[1600] as spongos transform;
* [Curve25519 asymmetric crypto](iota-streams-core-edsig/README.md) featuring Ed25519 signature and X25519 key exchange;
* [DDML](iota-streams-ddml/README.md) featuring data definition and manipulation language for protocol messages;
* [Application layer](iota-streams-app/README.md) common Application definitions.
* [Bindings](bindings/c/README.md).

The library is in the alpha stage and the API is likely to change.

|Table of contents|
|:----|
| [Streams](#overview)|
| [Prerequisites](#prerequisites)|
| [Getting started](#getting-started)|
| [API reference](#api-reference)|
| [Examples](#examples)|
| [License](#license)|

## Streams

IOTA Streams is a framework for cryptographic protocols called Applications. Streams ships with an existing application, called Channels. The Channels application builds on and extends functionality known from Masked Authenticated Messaging v0 and v1.0. 

As a cryptographic protocol framework, Streams allows developers to build Applications for their specific needs. This process will be documented in how-tos that will be published as the development progresses.

## Prerequisites

To use the library, we recommend update your Rust to latest stable version [`rustup update stable`](https://github.com/rust-lang/rustup.rs#keeping-rust-up-to-date). Nightly should be fine too.

`no_std` is currently supported. However cargo nightly must be used to build with `no_std` feature.

## Getting started

To use the library in your crate you need to add it as a dependancy in `Cargo.toml`, as it's not on [crates.io](https://crates.io/) it must be added from git repository:

```
[dependencies]
iota-streams = { git = "https://github.com/iotaledger/streams" }
```

Or you can clone the repository locally:

```
git clone https://github.com/iotaledger/streams
```

and add a dependency in `Cargo.toml` in the following way:

```
[dependencies]
iota-streams = { version = "0.2", path = "../streams" }
```

Optionally, you can run tests in the whole `iota-streams` project:

```
cd streams/
cargo test --all
```

Now you can use the Streams Channels Application in your code like this:

```
use iota_streams::app_channels::api::tangle::{Author, Subscriber};
use iota_streams::app::transport::tangle::PAYLOAD_BYTES;

fn main() {
    let encoding = "utf-8";
    let multi_branching_flag = true;

    let mut author = Author::new("AUTHORSSEED", encoding, PAYLOAD_BYTES, multi_branching_flag);
    
    let mut subscriber = Subscriber::new("MYSUBSCRIBERSECRETSTRING", encoding, PAYLOAD_BYTES);
}
```

For a more comprehensive example of using the Streams Channels Application can be found [here](examples/src/main.rs).

## API reference

API reference can be generated with the following command:
```
cargo doc --open
```

## Examples

Examples of using Channels Application can be found [here](examples/src/main.rs).

A full tutorial is available on [docs.iota.org](https://docs.iota.org/docs/channels/1.2/tutorials/build-a-messaging-app).

## License

The project is licensed under Apache 2.0/MIT license.
