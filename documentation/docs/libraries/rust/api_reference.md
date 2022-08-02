---
description: The official IOTA Streams Rust API reference.
image: /img/logo/iota_mark_light.png
keywords:
- api
- Rust
- api reference
- reference
---
# API Reference

There are two types of users: [Authors](../overview#authors) and [Subscribers](../overview#subscribers). An `Author` is the user that generates the channel, accepts subscription requests, and performs access granting and restriction methods. A `Subscriber` is a user that can subscribe to a channel to read from and write to (depending on the access privileges they have been granted).

You can generate the api reference with:

```bash
cargo doc --document
```





