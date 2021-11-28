# Examples
An overview example of the available api tools can be found [here](../../../../bindings/wasm/examples/node.js).
The general API is simply an abstraction over the rust library, so the examples found 
[here](../rust/examples.md) still apply (with some minor modifications, see: [api_reference](api_reference.md))

## Core Functionality

### Declare general setting
```javascript
let node = "https://chrysalis-nodes.iota.org/";
let options = new streams.SendOptions(node, true);
let client = await new streams.ClientBuilder().node(node).build();
```

### Author and Channel Generation
Create an Author and generate a new channel:
```javascript
let author = streams.Author.fromClient(streams.StreamsClient.fromClient(client), "Unique Seed", streams.ChannelType.SingleBranch);
let response = await author.clone().send_announce();
let ann_link = response.link;
// Link used by subscribers to attach to instance
console.log("Announced at: ", ann_link.toString());
```

### Subscriber Generation
Create a Subscriber and attach to a channel:
```javascript
let sub = new streams.Subscriber("Unique Seed", options.clone());
let ann_link = streams.Address.parse("Announcement_link_string:Here");
await sub.clone().receive_announcement(ann_link.copy());
```

### Subscriber subscribes to channel
Subscriber sends a subscription message:
```javascript
let response = sub.clone().send_subscribe(ann_link.copy());
let sub_link = response.link;
// Link to be provided to the Author for subscription
console.log("Subscription link: ", sub_link.toString());
```

### Author accepts and processes subscription: 
```javascript
let sub_link = streams.Address.parse("Sub_link_string:Here");
await author.clone().receive_subscribe(sub_link.copy());
```

### Keyload (case 1)
Author sends a keyload for all participants in the channel:
```javascript
let response = author.clone().send_keyload_for_everyone(ann_link.copy());
let keyload_link = response.link;
// Keyload message can now act as starting point for a protected branch
console.log("Keyload link for everyone: ", keyload_link.toString());
``` 

### Keyload (case 2)
Author sends a keyload for just one subscriber in the channel:
```javascript
let response = author.clone().send_keyload(ann_link.copy
(), [], ["SubA_PublicKey"]);
let sub_A_keyload_link = response.link;
// Keyload message can now act as starting point for a protected branch
console.log("Keyload link for SubA: ", sub_A_keyload_link.toString());
``` 

### Sending Messages
Messages are required to be linked to a previous message that the user had access to. 
In a single branch implementation this means the latest message in the branch, in multi
branch implementations, this can mean any message in a branch that they have had access 
to.

*Note: In a multi publisher implementation (i.e. multiple publishers in a single branch),
it is required that each publisher make sure to sync their state before publishing to ensure 
that the instance stays in sync with the other publishers*

```javascript
await sub.clone().sync_state();
let masked_payload = to_bytes("Masked Payload") <- Payloads must be converted to bytes
let public_payload = to_bytes("Public Payload")

let response = subA.clone().send_signed_packet(
    sub_A_keyload_link,
    public_payload,
    masked_payload
);
let msg_link = response.link;
console.log("New message sent by Sub A at: ", msg_link.toString());
```

### Message Fetching 
#### Forward
When new messages are available to retrieve from the channel, you can fetch the next 
message sent by each publisher like so:
```javascript
let next_msgs = sub.clone().fetch_next_msgs();

for (var i = 0; i < next_msgs.length; i++) {
    console.log("Found a message...");
    console.log(
      "Public: ",
      from_bytes(next_msgs[i].get_message().get_public_payload()),
      "\tMasked: ",
      from_bytes(next_msgs[i].get_message().get_masked_payload())
    );
}
```

If no new messages are present, the returned array will be empty.

You can also fetch all previous messages:

#### Backwards  
```javascript
let num_messages = 10;
let prev_msgs = sub.clone().fetch_prev_msgs(latest_msg_link, num_messages);

for (var i = 0; i < prev_msgs.length; i++) {
    console.log("Found a message...");
    console.log(
      "Public: ",
      from_bytes(prev_msgs[i].get_message().get_public_payload()),
      "\tMasked: ",
      from_bytes(prev_msgs[i].get_message().get_masked_payload())
    );
}
```
