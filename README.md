# IOTA Streams

This is the **WIP** Rust IOTA Streams library, it consists of the following components:
* [Channel Application](iota-streams-app-channel/README.md) featuring Channel Application.
* [Core layers](iota-streams-core/README.md) featuring utils for trinary/binary manipulations, sponge-based authenticated encryption with Troika permutation, pre-shared keys, pseudo-random generator;
* [Keccak for core layers](iota-streams-core-keccak/README.md) featuring Keccak-F[1600] as spongos transform;
* [Traversable Merkle tree](iota-streams-core-merkletree/README.md) featuring traversable Merkle tree;
* [Merkle signature](iota-streams-core-mss/README.md) featuring Merkle signature scheme over Winternitz one-time signature;
* [NTRU key encapsulation](iota-streams-core-ntru/README.md) featuring NTRU key encapsulation;
* [Protobuf3 layer](iota-streams-protobuf3/README.md) (not to be confused with Google's Protocol Buffers, though it was an inspiration for Protobuf3) featuring cryptographic message definition language;
* [Application layer](iota-streams-app/README.md) common Application definitions.

The library is in the beta stage and the API is likely to change.

|Table of contents|
|:----|
| [Streams](#overview)|
| [Prerequisites](#prerequisites)|
| [Getting started](#getting-started)|
| [API reference](#api-reference)
| [Examples](#examples)|
| [License](#license)|

## Streams

IOTA Streams is a framework for cryptographic protocols called Applications.

## Prerequisites

To use the library, we recommend update your Rust to latest stable version [`rustup update stable`](https://github.com/rust-lang/rustup.rs#keeping-rust-up-to-date). Nightly should be fine too.

`no_std` is not currently supported.

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
iota-streams = { version = "0.1", path = "../iota_streams" }
```

Optionally, you can run tests in the whole `iota-streams` project:

```
cd iota_streams/
cargo test --all
```

Now you can use the Streams Channel Application in your code like this:

```
use iota_streams_app_channel::api::tangle::{Author, Subscriber};

fn main() {
    let mut author = Author::new("AUTHORSSEED", 3, false);
    let mut subscriber = Subscriber::new("SUBSCRIBERSSEED", false);
}
```

For a more comprehensive example of using the Streams Channel Application can be found [here](iota-streams-app-channel/examples/basic_scenario.rs).

## API reference

API reference can be generated with the following command:
```
cargo doc --open
```

## Examples

Examples of using Channel Application can be found [here](iota-streams-app-channel/examples).

## License

The project is licensed under Apache 2.0/MIT license.
