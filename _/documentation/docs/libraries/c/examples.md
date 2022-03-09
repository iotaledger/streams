---
description: Official IOTA Streams C API examples.
image: /img/logo/iota_mark_light.png
keywords:
- api
- C
- examples
---
# Examples
An overview example of the available api tools can be found [here](../../../../bindings/c/main.c).
The general API is simply an abstraction over the rust library, so the examples found 
[here](../rust/examples.md) still apply (with some minor modifications, see: [api_reference](api_reference.md))

## Core Functionality

### Author Generation
Create an Author and generate a new channel:
```c
uint8_t multi_branching = 0;
char seed[] = "Some unique seed";
char const encoding[] = "utf-8";
const size_t size = 1024;
char const *url = "https://chrysalis-nodes.iota.org";

transport_t *tsp = tsp_client_new_from_url(url);
author_t *auth = auth_new(seed, encoding, size, multi_branching, tsp);
address_t const *ann_link = auth_send_announce(auth);
printf("Announcement message sent");

char const *ann_address_inst_str = get_address_inst_str(ann_link);
char const *ann_address_id_str = get_address_id_str(ann_link);
// Link used by subscribers to attach to instance
printf("Link: %s:%s\n", ann_address_inst_str, ann_address_id_str);

// Clean up
drop_str(ann_address_inst_str);
drop_str(ann_address_id_str);
drop_address(ann_link);
auth_drop(auth);
tsp_drop(tsp);
```

### Subscriber Generation
Create a Subscriber and attach to a channel:

```c
char seed[] = "Some unique seed";
char const encoding[] = "utf-8";
const size_t size = 1024;
char const *url = "https://chrysalis-nodes.iota.org";

transport_t *tsp = tsp_client_new_from_url(url);
subscriber_t *sub = sub_new(seed, encoding, size, tsp);

address_t const *ann_link = address_from_string("Announcement:Link");
sub_receive_announcement(sub, ann_link);

// Clean up
drop_address(ann_link);
sub_drop(sub);
tsp_drop(tsp);
```

### Subscription
Subscriber sends a subscription message:
```c
address_t const *sub_link = sub_send_subscribe(sub, ann_link);
char const *sub_inst_str = get_address_inst_str(ann_link);
char const *sub_id_str = get_address_id_str(ann_link);
// Link used by Author to process subscription
printf("Link: %s:%s\n", sub_inst_str, sub_id_str);

// Clean up
drop_str(sub_inst_str);
drop_str(sub_id_str);
drop_address(sub_link);
```

Author accepts and processes subscription: 
```c
address_t const *sub_link = address_from_string("Subscribe:Link");
auth_receive_subscribe(auth, sub_link);
drop_address(sub_link);
```

### Keyload
Author sends a keyload for all participants in the channel:
```c
message_links_t keyload_links = auth_send_keyload_for_everyone(auth, ann_link);
char const *keyload_inst_str = get_address_inst_str(keyload_links.msg_link);
char const *keyload_id_str = get_address_id_str(keyload_links.msg_link);
// Keyload message can now act as starting point for a protected branch
printf("Link: %s:%s\n", keyload_inst_str, keyload_id_str);

// Clean up
drop_str(keyload_inst_str);
drop_str(keyload_id_str);
drop_links(keyload_links);
```

Author sends a keyload for just one subscriber in the channel:
```c
sig_pks_t *sig_pks[sub_pk]
message_links_t keyload_links = auth_send_keyload(auth, ann_link, NULL, sig_pks);
char const *keyload_inst_str = get_address_inst_str(keyload_links.msg_link);
char const *keyload_id_str = get_address_id_str(keyload_links.msg_link);
// Keyload message can now act as starting point for a protected branch
printf("Link: %s:%s\n", keyload_inst_str, keyload_id_str);

// Clean up
drop_str(keyload_inst_str);
drop_str(keyload_id_str);
drop_links(keyload_links);
```

### Sending Messages
Messages are required to be linked to a previous message that the user had access to. 
In a single branch implementation this means the latest message in the branch, in multi
branch implementations, this can mean any message in a branch that they have had access 
to.

*Note: In a multi publisher implementation (i.e. multiple publishers in a single branch),
it is required that each publisher make sure to sync their state before publishing to ensure 
that the instance stays in sync with the other publishers*

```c
char const public_payload[] = "A public payload woopeee";
char const masked_payload[] = "A masked payload uhu";

sub_sync_state(sub);
message_links_t signed_packet_links = sub_send_signed_packet(
    sub, keyload_links,
    (uint8_t const *)public_payload, sizeof(public_payload),
    (uint8_t const *)masked_payload, sizeof(masked_payload)
);

char const *signed_packet_inst_str = get_address_inst_str(signed_packet_links.msg_link);
char const *signed_packet_id_str = get_address_id_str(signed_packet_links.msg_link);
printf("Signed Packet link: %s:%s\n", keyload_inst_str, keyload_id_str);

// Clean up
drop_str(signed_packet_inst_str);
drop_str(signed_packet_id_str);
drop_links(signed_packet_links);
```

### Message Fetching 
#### Forward
When new messages are available to retrieve from the channel, you can fetch the next 
message sent by each publisher like so:
```c
unwrapped_messages_t const *message_returns = sub_sync_state(subA);

size_t x;
for(x = 0; x < sizeof(message_returns); x++)
  {
    printf("Found a message...");
    packet_payloads_t response = get_indexed_payload(message_returns, x);
    printf("Unpacking message...\npublic: '%s' \tmasked: '%s'\n", response.public_payload.ptr, response.masked_payload.ptr);
  }

// Clean up
drop_unwrapped_messages(message_returns);
```

If no new messages are present, the returned array will be empty.

#### Backwards  
```c
size_t num_messages = 10;
unwrapped_messages_t const *prev_msgs = auth_fetch_prev_msgs(auth, latest_msg_link, num_messages);
printf("Previous messages retrieved... \n);

size_t x;
for(x = 0; x < sizeof(message_returns); x++)
  {
    printf("Found a message...");
    packet_payloads_t response = get_indexed_payload(message_returns, x);
    printf("Unpacking message...\npublic: '%s' \tmasked: '%s'\n", response.public_payload.ptr, response.masked_payload.ptr);
  }

// Clean up
drop_unwrapped_messages(prev_msgs);
```
