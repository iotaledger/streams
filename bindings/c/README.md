# IOTA Streams Application layer: C bindings

## Instructions

Change `src/constants.rs` to your preferred node and settings. (default to localhost)

Edit your author and subscriber seeds in `main.c`

run `./make` in this folder

Then run `cargo build --target-dir ./target` to build the rust code.

A binary will be generated which you can run in `./target/streams`
