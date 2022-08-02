---
description: Rust API Reference for the IOTA Streams Library.
image: /img/logo/wallet_light.png
keywords:
- Rust
- reference
- API reference
---
# Rust API Reference

There are two types of users: [Authors](../explanations/channels_protocol/authors) and [Subscribers](../explanations/channels_protocol/subscribers). An `Author` is the user that generates the channel, accepts subscription requests, and performs access granting and restriction methods. A `Subscriber` is a user that can subscribe to a channel to read from and write to (depending on the access privileges they have been granted).

You can generate the api reference with:

```bash
cargo doc --document
```





