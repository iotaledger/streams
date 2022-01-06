# Getting Started
Streams requires an asynchronous runtime environment to be set, we suggest using [tokio](https://docs.rs/tokio/latest/tokio/). Streams also uses [anyhow](https://docs.rs/anyhow/latest/anyhow/) for error handling, so projects can use `anyhow::Result` and `anyhow::Error` for easier integration. 

To create a new Rust project, run:

```bash
cargo new PROJECT_NAME
```

Create two of these Rust projects, one for the author and one for the subscriber, and add the following dependencies to both their `Cargo.toml` files:

```toml
tokio = { version = "1.5.0", features = ["full"] }
anyhow = { version = "1.0" }
iota-streams = { git = "https://github.com/iotaledger/streams", branch = "develop"}

# Temporarily needed because Streams is a work in progress
bee-message = "=0.1.5"
bee-rest-api = "=0.1.2"
```

## Basic Usage
With the needed projects and their dependencies added, we can start using the Streams library. Below are two example scripts for both the author and the subscriber. The author script will announce a channel and print the announcement link. The subscriber script handles the announcement to let the subscriber know where to find the channel.
 
### Author
Replace the seed of the author with a random string and run the script to get the announcement link.

```
use anyhow::Result;
use iota_streams::app_channels::api::tangle::{Author, ChannelType};
use iota_streams::app::transport::tangle::client::Client;

#[tokio::main]
async fn main() -> Result<()> {
    let node = "https://chrysalis-nodes.iota.org";
    let client = Client::new_from_url(node);

    // Author implementation will set the Channel Type
    let mut author = Author::new("AUTHOR_SEED", ChannelType::SingleBranch, client);
    
    // Start the channel and retrieve the announcement link
    let ann_link = author.send_announce().await?;   

    // Convert the announcement link to a string to share with others
    println!("{}", ann_link.to_string());
    Ok(())
}
```

### Subscriber
Replace the seed of the subscriber with a random string, paste the announcement link from the author script above and run the script to let the subscriber find the channel.

```
use anyhow::Result;
use iota_streams::app_channels::api::tangle::{Address, Subscriber};
use iota_streams::app::transport::tangle::client::Client;
use std::str::FromStr;

#[tokio::main]
async fn main() -> Result<()> {
    let node = "https://chrysalis-nodes.iota.org";
    let client = Client::new_from_url(node);

    // Subscriber implementation does not need to specify a channel type, it will be 
    // parsed from the announcement message
    let mut subscriber = Subscriber::new("SUBSCRIBER_SEED", client);
    
    // Create Address object from announcement link string
    let ann_link = Address::from_str("ANNOUNCEMENT_LINK")?;   

    // Process the announcement message
    subscriber.receive_announcement(&ann_link).await?;
    Ok(())
}
```

## Next Steps
Now we can begin subscribing users to the channel and generating branches to specify access control for publishers and subscribers via keyload messages.  

### Subscription
To subscribe to a channel, subscribers create a subscribe message that is linked to the channel announcement message. The link of this message should then be provided to the author. This allows the author to handle the subscription message and use the public key of the subscriber for access control and validation purposes.

#### Subscriber
```
// Send subscription message
let sub_link = subscriber.send_subscribe(&ann_link).await?;
// Provide the link to the author
println!("{}", sub_link.to_string());
```

#### Author
```
// Process subscriber link 
let sub_link = Address::from_str("SUBSCRIPTION_LINK")?;
author.receive_subscribe(&sub_link).await?;
```

### Keyloads 
Keyload messages are used as an access control mechanism for a branch. A random key is generated and masked within the message using the public keys or pre-shared keys included in them. This allows the author to specify which subscribers have access to which branches. There are two ways to send a keyload:
- Send a keyload including specific pre-shared keys or subscriber public keys.
- Send a keyload including all pre-shared keys and subscriber public keys known to the author.

Example: 
```
// Send keyload including pre-shared key
let psk = psk_from_seed("KEY_SEED".as_bytes());
let psk_id = pskid_from_psk(&psk);
author.store_psk(psk_id, psk)?;
author.send_keyload(&ann_link, &vec![psk_id.into()]).await?;

// Send keyload for subscriber
author.send_keyload(&ann_link, &vec![subscriber_public_key.into()]).await?;

// Send keyload for everyone
author.send_keyload_for_everyone(&ann_link).await?;
```

### Pre-shared keys 
As an alternative to subscribing via public key exchange using subscribe messages, an author may specify access control through the use of a pre-shared key (PSK). A PSK is a 32 byte array containing a secret key, shared outside of the Streams instance, that can be used to specify access through a keyload message. If an author issues a keyload with a PSK included, and a subscriber reads this message with the same PSK stored within itself, then the subscriber can participate in the proceeding branch without being subscribed to the channel. 

Example: 
```
use iota_streams::app_channels::api::{psk_from_seed, pskid_from_psk};
use rand::Rng;

// Create a random key
let key_seed = rand::thread_rng().gen::<[u8; 32]>();
let psk = psk_from_seed(&key);
let pskid = pskid_from_psk(&psk);

// Store the PSK in the author
author.store_psk(pskid, psk)?;

// Create a keyload with the PSK included
let keyload_link = author.send_keyload(&ann_link, &vec![psk_id.into()]).await?;

// Store the same PSK in the subscriber 
subscriber.store_psk(pskid, psk);

// Process keyload message from subscriber end
subscriber.receive_keyload(&keyload_link).await?;
```
