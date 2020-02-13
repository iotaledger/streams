# IOTA MAM v1.1

This is the **WIP** Rust IOTA MAM library, it consists of the following components:
* [Core layers](iota-mam-core/README.md) featuring utils for trits manipulations, sponge-based authenticated encryption with Troika permutation, Merkle signature scheme, NTRU-like key encapsulation;
* [Protobuf3 layer](iota-mam-protobuf3/README.md) (not to be confused with Google's Protocol Buffers, though it was an inspiration for Protobuf3) featuring cryptographic message definition language;
* [Application layer](iota-mam-app/README.md) featuring Channel Application.

The library is in the beta stage and the API is likely to change.

|Table of contents|
|:----|
| [MAM v1.1](#overview)|
| [Prerequisites](#prerequisites)|
| [Using the library](#installing-the-library)|
| [Getting started](#getting-started)|
| [API reference](#api-reference)
| [Examples](#examples)|
| [License](#license)|

## MAM v1.1

IOTA MAM v1.1 is a framework for cryptographic protocols called Applications.

The current specification can be found [here](spec.pdf). The slides providing a slight in-depth insight on MAM v1.1 can be found [here](slides.pdf).

## Prerequisites

To use the library, we recommend update your Rust to latest stable version [`rustup update stable`](https://github.com/rust-lang/rustup.rs#keeping-rust-up-to-date). Nightly should be fine too.

`no_std` is not currently supported.

## Using the library

Using the library is fairly easy, just add it as dependancy in `Cargo.toml`:

```
[dependencies]
iota-mam = "0.1"
```

## Getting started

## API reference

API reference can be generated with the following command:
```
cargo doc --open
```

## Examples

Examples of using Channel Application can be found [here](iota-mam-app/examples).

## License

The project is licensed under Apache 2.0/MIT license.
