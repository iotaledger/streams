# Getting Started
Streams requires an asynchronous runtime environment to be set (we suggest using `tokio`). Streams also uses 
`anyhow` for error handling, so for ease of use, new projects can use `anyhow::Result` and `anyhow::Error` 
for easier integration. 


If you don't have a rust project setup yet you can create one by running,

    cargo new my-library

**Remote**
Add the following to your `Cargo.toml` file:

```bash
[dependencies]
tokio = { version = "1.5.0", features = ["full"] }
anyhow = { version = "1.0", default-features = false }
iota-streams = { git = "https://github.com/iotaledger/streams", branch  = "master"}
```

**Local**

1. Clone the streams repository

    ```bash
    git clone https://github.com/iotaledger/streams
    ```

2. Add the following to your `Cargo.toml` file:

    ```bash
    [dependencies]
    iota-streams = { version = "1.0.0", path = "../streams" }
    ```

## Basic Usage
Once installed, users can implement their author and subscribers and start a new channel.
 
### Author Implementation
```
use iota_streams::app_channels::api::tangle::{Author, ChannelType};
use iota_streams::app::transport::tangle::client::Client;

#[tokio::main]
async fn main() -> Result<()> {
    let node = "https://chrysalis-nodes.iota.org";
    let client = Client::new_from_url(node);

    // Author implementation will set the Channel Type
    let mut author = Author::new("AUTHORS_UNIQUE_SEED", ChannelType::SingleBranch, client);
    
    // Start the channel and retrieve the announcement address link
    let ann_address = author.send_announce()?;   

    // Convert the announcement address to a string to share with others
    println!("{}", ann_address.to_string()); 
}
```

### Subscriber Implementation
```
use iota_streams::app_channels::api::tangle::{Address, Subscriber};
use iota_streams::app::transport::tangle::client::Client;

#[tokio::main]
async fn main() -> Result<()> {
    let node = "https://chrysalis-nodes.iota.org";
    let client = Client::new_from_url(node);

    // Subscriber implementation does not need to specify a channel type, it will be 
    // parsed from the announcement message
    let mut subscriber = Subscriber::new("SUBSCRIBER_UNIQUE_SEED", client);
    
    // Create Address object from announcement address string
    let ann_address = Address::from_str("Announcement link address provided by author")?;   

    // Process the announcement message
    subscriber.receive_announcement(ann_address)?;
}
```

## Next Steps
From here you can now begin subscribing users to the channel and generating branches to specify access control 
for publishers/readers via `Keyload` messages.  

### Subscription 
Subscribers generate their `Subscribe` messages linked to a channel `Announce` message. The link of this message 
should then be provided to the `Author` for processing to include the users public key for access control and 
validation purposes.

Example: 
```
Subscriber: 
// Send subscription message
let sub_link = subscriber.send_subscribe(&ann_address)?;
// Provide this link to the author
println!("{}", sub_link.to_string());
```

```
Author: 
// Process subscriber link 
let sub_link = Address::from_str("Sub link provided by desired subscriber")?;
author.receive_subscribe(&sub_link)?;
```

### Keyloads 
`Keyload` messages are used as an access control mechanism for a branch. A random key is generated and masked within the 
message using the public keys or `Psk`'s included in them. This allows the `Author` to specify which channel 
participants have access to which branches. There are 2 ways to send a keyload: 
1. `send_keyload(&Address, &Vec<PskId>, &Vec<PublicKey>)` - In this function you need to specify:
    - the message link that the `Keyload` message will be attached to (for generating new branches, this should be the 
    `Announce` message) 
    - a slice containing the `PskId`'s of the Pre-Shared Keys intended to be included 
    - a slice containing the `ed25519::PublicKey`'s of each `Subscriber` that is meant to be granted access 
2. `send_keyload_for_everyone(&Address)` - In this function you only need to specify the message link that the `Keyload` 
will be attaching to. The `Keyload` will be sent including all stored `PSK`'s and all stored `Subscriber` public keys 

Example: 
```
// Send Keyload for everyone (starting a new branch) 
author.send_keyload_for_everyone(&announcement_link)?;

// Send Keyload including Pre Shared Key 2 
author.send_keyload(&announcement_link, &vec![PskId2], &vec![])?;

// Send Keyload for Subscriber 3
author.send_keyload(&announcement_link, &vec![], &vec![subscriber_3_pub_key])?;
```

### Pre-Shared Keys 
As an alternative to subscribing via public key exchange, an `Author` may specify access control through the use of 
a Pre-Shared Key (`PSK`). A `PSK` is a 32 byte array containing a secret key shared outside of the streams instance 
that can be used to specify access through a `Keyload` message. If an `Author` issues a `Keyload` with a `PSK` included, 
and a `Subscriber` reads this message with the same `PSK` stored within itself, then the `Subscriber` can participate in 
the proceeding branch without being subscribed to the channel. 

Example: 
```
// Create a random key (for example) and make the Psk from it
let key = rand::thread_rng().gen::<[u8; 32]>();
let psk = iota_streams::core::psk::Psk::clone_from_slice(&key);

// Store the psk and retrieve the pskid
let pskid = author.store_psk(psk.clone());

// Create a keyload with the psk included
let keyload_link = author.send_keyload(&prev_msg_link, &vec![pskid], &vec![])?;

// Store the same psk in subscriber 
let _sub_pskid = subscriber.store_psk(psk);

// Process keyload message from subscriber end
subscriber.receive_keyload(&keyload_link)?;
```

