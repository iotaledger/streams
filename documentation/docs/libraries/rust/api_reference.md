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

Users are broken down into two types: `Author` and `Subscriber`. An `Author` is the user that generates the channel, accepts subscription requests, and performs access granting and restriction methods. A `Subscriber` is an instance that can attach to a channel to read-from and write-to depending on the access privileges they have been granted. 

You can generate the api reference with:

```
cargo doc --document
```





