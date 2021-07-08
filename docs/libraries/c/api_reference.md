# Iota Streams C Bindings API Reference

### Author

#### auth_new(seed, encoding, payload_length, multi_branching, tsp): author_t 
Generates an Author instance 

| Param           | Type                                   | Description              |
| --------------- | -------------------------------------- | ------------------------ |
| seed            | `char const *`                         | Unique user seed         |
| encoding        | `char const *`                         | Payload encoding         |
| payload_length  | `size_t`                               | Payload max length       |
| multi_branching | `uint8_t`                              | Channel Type             | 
| tsp             | [`transport_t *`](#TransportWrap)      | Transport Client Wrapper |
**Returns:** An Author instance for administrating a channel.

#### auth_recover(seed, announcement, multi_branching, tsp): author_t 
Recover an Author instance using the announcement address link and seed.

| Param           | Type                                   | Description              |
| --------------- | -------------------------------------- | ------------------------ |
| seed            | `char const *`                         | Unique user seed         |
| announcement    | [`address_t const *`](#Address)        | Announcement link        |
| multi_branching | `uint8_t`                              | Channel Type             | 
| tsp             | [`transport_t *`](#TransportWrap)      | Transport Client Wrapper |
**Returns:** A recovered Author instance for administrating a channel.

#### auth_drop(user)
Drop an Author instance from memory.

| Param           | Type                                   | Description              |
| --------------- | -------------------------------------- | ------------------------ |
| user            | `author_t *`                           | Author instance          |



#### auth_import(buffer, password, transport): author_t 
Import an Author instance from an encrypted binary array

| Param           | Type                                   | Description               |
| --------------- | -------------------------------------- | ------------------------- |
| bytes           | `buffer_t`                             | Buffer with exported data |
| password        | `char const *`                         | Key to decrypt binary     | 
| transport       | [`transport_t *`](#TransportWrap)      | Transport Client Wrapper  |
**Returns:** A recovered Author instance for administrating a channel.

#### auth_export(user, password): buffer_t 
Export an Author instance as an encrypted array using a given password

| Param           | Type                | Description               |
| --------------- | ------------------- | ------------------------- |
| user            | `author_t *`        | Author instance           |
| password        | `char const *`       | Key to encrypt            | 
**Returns:** Binary array representing an encrypted state of the author.


#### auth_channel_address(user): [channel_address_t const *](#ChannelAddress) 
Return the channel address of the channel instance. 

| Param           | Type                | Description               |
| --------------- | ------------------- | ------------------------- |
| user            | `author_t const *`  | Author instance           |
**Returns:** Channel Address for user generated channel.

#### auth_is_multi_branching(user): uint8_t 
Check if a channel type is single branching or multi branching. 

| Param           | Type                | Description               |
| --------------- | ------------------- | ------------------------- |
| user            | `author_t const *`  | Author instance           |
**Returns:** Uint8_t representing the channel type: 0=single branch, 1=multi branch.

#### auth_get_public_key(user): [public_key_t const *](#PublicKey) 
Retrieve the Author public key.

| Param           | Type                | Description               |
| --------------- | ------------------- | ------------------------- |
| user            | `author_t const *`     | Author instance        |
**Returns:** The Author public key.


#### auth_send_announce(user): [address_t const *](#Address)
Send an announcement message, initialising the channel 

| Param           | Type                | Description               |
| --------------- | ------------------- | ------------------------- |
| user            | `author_t *`        | Author instance           |
**Returns:** The address of the announcement message.

#### auth_send_keyload_for_everyone(links, author, link_to): [err_t](#Err)
Send a keyload message for all subscribed participants in the channel, linked to a previous message 
(usually the announcement in a multi branch).

| Param           | Type                                 | Description                        |
| --------------- | ------------------------------------ | ---------------------------------- |
| links           | [`message_links_t *`](#MessageLinks) | Resulting Message Links wrapper around the keyload message link and sequence link. |
| author          | `author_t *`                         | Author instance                    |
| link_to         | [`address_t const *`](#Address)      | Address of message being linked to |
**Returns:** Error code.

#### auth_send_keyload(links, author, link_to, psk_ids, ke_pks): [err_t](#Err)
Send a keyload message for specified subscribers and pre shared keys in the channel, linked to a previous 
message (usually the announcement in a multi branch).

| Param           | Type                                 | Description                                   |
| --------------- | ------------------------------------ | --------------------------------------------- |
| links           | [`message_links_t *`](#MessageLinks) | Resulting Message Links wrapper around the keyload message link and sequence link. |
| author          | `author_t *`                         | Author instance                               |
| link_to         | [`address_t const *`](#Address)      | Address of message being linked to            |
| psk_ids         | [`psk_ids_t *`](#PskIds)             | Array of PskId's for included subscribers     |
| ke_pks          | [`ke_pks_t *`](#PublicKeys)          | Array of Public Keys for included subscribers |
**Returns:** Error code.

#### auth_receive_subscribe(author, link): [err_t](#Err)
Process a subscription message by its link.

| Param           | Type                            | Description                         |
| --------------- | ------------------------------- | ----------------------------------- |
| author          | `author_t *`                    | Author instance                     |
| link            | [`address_t const *`](#Address) | Address of subscription message     |
**Returns:** Error code.

#### auth_send_tagged_packet(links, author, link_to, public_payload_ptr, public_payload_size, masked_payload_ptr, masked_payload_size): [err_t](#Err)
Send a tagged packet message linked to a previous message.

| Param              | Type                                 | Description                                   |
| ------------------ | ------------------------------------ | --------------------------------------------- |
| links              | [`message_links_t *`](#MessageLinks) | Resulting Message Links wrapper around the tagged packet link and sequence link. |
| author             | `author_t *`                         | Author instance                               |
| link_to            | [`message_links_t`](#MessageLinks)   | Address of message being linked to            |
| public_payload_ptr | `uint8_t const *`                    | Byte array of public payload pointer          |
| public_payload_size| `size_t`                             | Length of public payload byte array           |
| masked_payload_ptr | `uint8_t const *`                    | Byte array of masked payload pointer          |
| masked_payload_size| `size_t`                             | Length of masked payload byte array           |
**Returns:** Error code.

#### auth_send_signed_packet(links, author, link_to, public_payload_ptr, public_payload_size, masked_payload_ptr, masked_payload_size): [err_t](#Err)
Send a signed packet message linked to a previous message.

| Param              | Type                              | Description                                   |
| ------------------ | --------------------------------- | --------------------------------------------- |
| links              | [`message_links_t *`](#MessageLinks)   | Resulting Message Links wrapper around the signed packet link and sequence link. |
| author             | `author_t *`                      | Author instance                               |
| link_to            | [`message_links_t`](#MessageLinks)| Address of message being linked to            |
| public_payload_ptr | `uint8_t const *`                 | Byte array of public payload pointer          |
| public_payload_size| `size_t`                          | Length of public payload byte array           |
| masked_payload_ptr | `uint8_t const *`                 | Byte array of masked payload pointer          |
| masked_payload_size| `size_t`                          | Length of masked payload byte array           |
**Returns:** Error code.

#### auth_receive_tagged_packet(payloads, author, link): [err_t](#Err)
Receive a tagged packet by its link.

| Param           | Type                                     | Description                         |
| --------------- | ---------------------------------------- | ----------------------------------- |
| payloads        | [`packet_payloads_t *`](#PacketPayloads) | Resulting Packet Payloads wrapper around the tagged packet message |
| author          | `author_t *`                             | Author instance                     |
| link            | [`address_t const *`](#Address)          | Address of tagged packet message    |
**Returns:** Error code.

#### auth_receive_signed_packet(payloads, author, link): [err_t](#Err)
Receive a signed packet by its link.

| Param           | Type                          | Description                                    |
| --------------- | ---------------------------------------- | ----------------------------------- |
| payloads        | [`packet_payloads_t *`](#PacketPayloads) | Resulting Packet Payloads wrapper around the signed packet message |
| author          | `author_t *`                             | Author instance                     |
| link            | [`address_t const *`](#Address)          | Address of signed packet message    |
**Returns:** Error code.

#### auth_receive_sequence(seq, author, link): [err_t](#Err)
Receive a sequence message by its link, and return the address of the sequenced message. 

| Param           | Type                             | Description                         |
| --------------- | -------------------------------- | ----------------------------------- |
| seq             | [`address_t const **`](#Address) | The address link of the sequenced message. |
| author          | `author_t *`                     | Author instance                     |
| link            | [`address_t const *`](#Address)  | Address of sequence message         |
**Returns:** Error code.

#### auth_receive_msg(umsg, author, link): [err_t](#Err)
Receive a message generically without knowing its type.

| Param           | Type                                             | Description                          |
| --------------- | ------------------------------------------------ | ------------------------------------ |
| umsg            | [unwrapped_message_t const *](#UnwrappedMessage) | An Unwrapped Message wrapper around the retrieved message. |
| author          | `author_t *`                                     | Author instance                     |
| link            | [`address_t const *`](#Address)                  | Address of sequence message         |
**Returns:** Error code.

#### auth_sync_state(author): [unwrapped_messages_t const *](#UnwrappedMessages)
Synchronise a publishers state prior to sending another message. Retrieves any other messages from the channel 
to ensure the user state matches all other publishers.

| Param           | Type                          | Description                         |
| --------------- | ----------------------------- | ----------------------------------- |
| author          | `author_t *`                  | Author instance                     |
**Returns:** An Array of UnwrappedMessage wrappers around the retrieved messages.

#### auth_fetch_next_msgs(author): [unwrapped_messages_t const *](#UnwrappedMessages)
Fetch the next message sent by each publisher (empty array if none are present).

| Param           | Type                          | Description                         |
| --------------- | ----------------------------- | ----------------------------------- |
| author          | `author_t *`                  | Author instance                     |
**Returns:** An array of UnwrappedMessage wrappers around the retrieved messages.

#### auth_gen_next_msg_ids(author): [next_msg_ids_t const *](#NextMsgIds)
Fetch the next message sent by each publisher (empty array if none are present).

| Param           | Type                          | Description                         |
| --------------- | ----------------------------- | ----------------------------------- |
| author          | `author_t *`                  | Author instance                     |
**Returns:** An array of NextMsgId wrappers for each publisher in the channel.

#### auth_fetch_state(author): [user_state_t const *](#UserState)
Fetch the current user state to see the latest links for each publisher

| Param           | Type                          | Description                         |
| --------------- | ----------------------------- | ----------------------------------- |
| author          | `author_t *`                  | Author instance                     |


#### auth_store_state(author, psk): pskid_t 
Stores a given Pre Shared Key (Psk) into the Author instance, returning a Pre Shared Key Id (PskId) 

| Param           | Type                                   | Description              |
| --------------- | -------------------------------------- | ------------------------ |
| author          | `author_t *`                           | Author instance          |
| psk             | `char const *`                         | Unique Pre Shared Key    |
**Returns:** A PskId representing the Psk stored in the instance.


### Subscriber 

#### sub_new(seed, encoding, payload_length, transport): Subscriber 
Generates an Author instance 

| Param           | Type                                   | Description              |
| --------------- | -------------------------------------- | ------------------------ |
| seed            | `char const *`                         | Unique user seed         |
| encoding        | `char const *`                         | Payload encoding         |
| payload_length  | `size_t`                               | Payload max length       |
| transport       | [`transport_t *`](#TransportWrap)      | Transport Client Wrapper |
**Returns:** A Subscriber instance for publishing to and reading from a channel.

#### sub_recover(seed, announcement, transport): Subscriber 
Recover an Author instance using the announcement address link and seed.

| Param           | Type                                   | Description              |
| --------------- | -------------------------------------- | ------------------------ |
| seed            | `char const *`                         | Unique user seed         |
| announcement    | [`address_t const *`](#Address)        | Announcement link        |
| transport       | [`transport_t *`](#TransportWrap)      | Transport Client Wrapper |
**Returns:** A recovered Subscriber instance for publishing to and reading from a channel.

#### sub_drop(user)
Drop a Subscriber instance from memory.

| Param           | Type                                   | Description              |
| --------------- | -------------------------------------- | ------------------------ |
| subscriber | `subscriber_t *`                       | Subscriber instance      |


#### sub_import(buffer, password, transport): Subscriber 
Import a Subscriber instance from an encrypted binary array 

| Param           | Type                                   | Description               |
| --------------- | -------------------------------------- | ------------------------- |
| buffer          | `buffer_t`                             | Buffer with exported data |
| password        | `char const *`                         | Key to decrypt binary     | 
| transport       | [`transport_t *`](#TransportWrap)      | Transport Client Wrapper  |
**Returns:** A recovered Subscriber instance for publishing to and reading from a channel.

#### sub_export(subscriber, password): Buffer 
Export an Author instance as an encrypted array using a given password

| Param           | Type                   | Description               |
| --------------- | ---------------------- | ------------------------- |
| subscriber      | `subscriber_t const *` | Subscriber instance       |
| password        | `char const *`         | Key to encrypt            | 
**Returns:** Binary array representing an encrypted state of the Subscriber.


#### sub_channel_address(subscriber): [channel_address_t const *](#ChannelAddress) 
Return the channel address of the channel instance. 

| Param           | Type                | Description               |
| --------------- | ------------------- | ------------------------- |
| subscriber      | `subscriber_t const *` | Subscriber instance    |
**Returns:** Channel Address for subscriber generated channel.

#### sub_is_multi_branching(subscriber): uint8_t 
Check if a channel type is single branching or multi branching. 

| Param           | Type                   | Description               |
| --------------- | ---------------------- | ------------------------- |
| subscriber      | `subscriber_t const *` | Subscriber instance       |
**Returns:** Uint8_t representing the channel type: 0=single branch, 1=multi branch.

#### sub_get_public_key(subscriber): [public_key_t const *](#PublicKey) 
Retrieve the Subscriber public key.

| Param           | Type                   | Description               |
| --------------- | ---------------------- | ------------------------- |
| subscriber      | `subscriber_t const *` | Subscriber instance       |
**Returns:** The Subscriber public key.

#### sub_is_registered(subscriber): uint8_t 
Check if subscriber has processed an announcement message.

| Param           | Type                   | Description               |
| --------------- | ---------------------- | ------------------------- |
| subscriber      | `subscriber_t const *` | Subscriber instance       |
**Returns:** Uint8 representing if the Subscriber has processed an announcement. 0=false, 1=true.

#### sub_unregister(subscriber) 
Unregister the subscriber from a channel.

| Param           | Type                | Description               |
| --------------- | ------------------- | ------------------------- |
| subscriber      | `subscriber_t *`    | Subscriber instance       |

#### sub_receive_announcement(subscriber, address): [err_t](#Err)
Process an announcement message by its link.

| Param           | Type                            | Description                         |
| --------------- | ------------------------------- | ----------------------------------- |
| subscriber      | `subscriber_t *`                | Subscriber instance                 |
| address         | [`address_t const *`](#Address) | Address of announcement message     |
**Returns:** Error code.


#### sub_send_subscribe(link, subscriber, announcement_link): [err_t](#Err)
Send a subscription message, initialising the channel 

| Param             | Type                             | Description               |
| ----------------- | -------------------------------- | ------------------------- |
| link              | [`address_t const **`](#Address) | The address of the subscription message. |
| subscriber         | `subscriber_t *`                | Subscriber instance       |
| announcement_link | [`address_t const *`](#Address)  | Announcement link         |
**Returns:** Error code.

#### sub_send_tagged_packet(links, subscriber, link_to, public_payload_ptr, public_payload_size, masked_payload_ptr, masked_payload_size): [err_t](#Err)
Send a tagged packet message linked to a previous message.

| Param              | Type                                 | Description                                   |
| ------------------ | ------------------------------------ | --------------------------------------------- |
| links              | [`message_links_t *`](#MessageLinks) | Resulting Message Links wrapper around the tagged packet link and sequence link. |
| subscriber         | `subscriber_t *`                     | Subscriber instance                           |
| link_to            | [`message_links_t`](#MessageLinks)   | Address of message being linked to            |
| public_payload_ptr | `uint8_t const *`                    | Byte array of public payload pointer          |
| public_payload_size| `size_t`                             | Length of public payload byte array           |
| masked_payload_ptr | `uint8_t const *`                    | Byte array of masked payload pointer          |
| masked_payload_size| `size_t`                             | Length of masked payload byte array           |
**Returns:** Error code.

#### sub_send_signed_packet(links, subscriber, link_to, public_payload_ptr, public_payload_size, masked_payload_ptr, masked_payload_size): [err_t](#Err)
Send a signed packet message linked to a previous message. 

| Param              | Type                                 | Description                                   |
| ------------------ | ------------------------------------ | --------------------------------------------- |
| links              | [`message_links_t *`](#MessageLinks) | Resulting Message Links wrapper around the signed packet link and sequence link. |
| subscriber         | `subscriber_t *`                     | Subscriber instance                           |
| link_to            | [`message_links_t`](#MessageLinks)   | Address of message being linked to            |
| public_payload_ptr | `uint8_t const *`                    | Byte array of public payload pointer          |
| public_payload_size| `size_t`                             | Length of public payload byte array           |
| masked_payload_ptr | `uint8_t const *`                    | Byte array of masked payload pointer          |
| masked_payload_size| `size_t`                             | Length of masked payload byte array           |
**Returns:** Error code.

#### sub_receive_keyload(subscriber, address): [err_t](#Err)
Receive a keyload packet by its link.

| Param           | Type                            | Description                         |
| --------------- | ------------------------------- | ----------------------------------- |
| subscriber      | `subscriber_t *`                | Subscriber instance                 |
| address         | [`address_t const *`](#Address) | Address of keyload message          |
**Returns:** Error code.

#### sub_receive_keyload_from_ids(links, subscriber, next_msg_ids): [err_t](#Err)
Receive a keyload packet by a set of next msg ids.

| Param           | Type                                    | Description                         |
| --------------- | --------------------------------------- | ----------------------------------- |
| links           | [`message_links_t *`](#MessageLinks)    | Resulting Message Links wrapper around the keyload message link and sequence link. |
| subscriber      | `subscriber_t *`                        | Subscriber instance                 |
| next_msg_ids    | [`next_msg_ids_t const *`](#NextMsgIds) | Address of keyload message          |
**Returns:** Error code.


#### sub_receive_tagged_packet(payloads, subscriber, address): [err_t](#Err)
Receive a tagged packet by its link.

| Param           | Type                                     | Description                         |
| --------------- | ---------------------------------------- | ----------------------------------- |
| payloads        | [`packet_payloads_t *`](#PacketPayloads) | Resulting Packet Payloads wrapper around the tagged packet message |
| subscriber      | `subscriber_t *`                         | Subscriber instance                 |
| address         | [`address_t const *`](#Address)          | Address of tagged packet message    |
**Returns:** Error code.

#### sub_receive_signed_packet(payloads, subscriber, address): [err_t](#Err)
Receive a signed packet by its link.

| Param           | Type                                     | Description                         |
| --------------- | ---------------------------------------- | ----------------------------------- |
| payloads        | [`packet_payloads_t *`](#PacketPayloads) | Resulting Packet Payloads wrapper around the signed packet message |
| subscriber      | `subscriber_t *`                         | Subscriber instance                 |
| address         | [`address_t const *`](#Address)          | Address of signed packet message    |
**Returns:** Error code.

#### sub_receive_sequence(address, subscriber, seq_address): [err_t](#Err)
Receive a sequence message by its link, and return the address of the sequenced message. 

| Param           | Type                             | Description                                |
| --------------- | -------------------------------- | ------------------------------------------ |
| address         | [`address_t const **`](#Address) | The address link of the sequenced message. |
| subscriber      | `subscriber_t *`                 | Subscriber instance                        |
| seq_address     | [`address_t const *`](#Address)  | Address of sequence message                |
**Returns:** Error code.

#### sub_receive_msg(umsg, subscriber, address): [err_t](#Err)
Receive a message generically without knowing its type.

| Param           | Type                                             | Description                          |
| --------------- | ------------------------------------------------ | ------------------------------------ |
| umsg            | [unwrapped_message_t const *](#UnwrappedMessage) | An Unwrapped Message wrapper around the retrieved message. |
| subscriber      | `subscriber_t *`                                 | Subscriber instance                  |
| address         | [`address_t const *`](#Address)                  | Address of the message               |
**Returns:** Error code.

#### sub_sync_state(umsgs, subscriber): [err_t](#Err)
Synchronise a publishers state prior to sending another message. Retrieves any other messages from the channel 
to ensure the subscriber state matches all other publishers.

| Param           | Type                          | Description                         |
| --------------- | ----------------------------- | ----------------------------------- |
| umsgs           | [`unwrapped_messages_t const **`](#UnwrappedMessages) | An Array of UnwrappedMessage wrappers around the retrieved messages. |
| subscriber      | `subscriber_t *`             | Subscriber instance                 |
**Returns:** Error code.

#### sub_fetch_next_msgs(umsgs, subscriber): [err_t](#Err)
Fetch the next message sent by each publisher (empty array if none are present).

| Param           | Type                          | Description                         |
| --------------- | ----------------------------- | ----------------------------------- |
| umsgs           | [`unwrapped_messages_t const **`](#UnwrappedMessages) | An Array of UnwrappedMessage wrappers around the retrieved messages. |
| subscriber       | `subscriber_t *`             | Subscriber instance                 |
**Returns:** Error code.

#### sub_gen_next_msg_ids(subscriber): [next_msg_ids_t const *](#NextMsgIds)
Fetch the next message sent by each publisher (empty array if none are present).

| Param           | Type                          | Description                         |
| --------------- | ----------------------------- | ----------------------------------- |
| subscriber       | `subscriber_t *`             | Subscriber instance                 |
**Returns:** An array of NextMsgId wrappers for each publisher in the channel.

#### sub_fetch_state(subscriber): [*const UserState](#UserState)
Fetch the current subscriber state to see the latest links for each publisher

| Param           | Type                          | Description                         |
| --------------- | ----------------------------- | ----------------------------------- |
| subscriber       | `subscriber_t *`             | Subscriber instance                 |


#### sub_store_state(subscriber, psk): pskid_t 
Stores a given Pre Shared Key (Psk) into the Subscriber instance, returning a Pre Shared Key Id (PskId) 

| Param           | Type                                   | Description              |
| --------------- | -------------------------------------- | ------------------------ |
| author          | `subscriber_t *`                       | Subscriber instance      |
| psk             | `char const *`                         | Unique Pre Shared Key    |
**Returns:** A PskId representing the Psk stored in the instance.



## Types

### Err
Error code

| Value                | Description                             |
| -------------------  | --------------------------------------- |
| ERR_OK               | Success, no errors                      |
| ERR_NULL_ARGUMENT    | Null-pointer argument                   |
| ERR_BAD_ARGUMENT     | An invalid argument was given as input  |
| ERR_OPERATION_FAILED | Transport, wrap/unwrap operation failed |

### TransportDetails

### TransportWrap 
#### transport_new(): transport_t *
Generate a default transport client object (best for testing purposes)

| Param           | Type                          | Description                         |
| --------------- | ----------------------------- | ----------------------------------- |
**Returns:** A generic transport client wrap
 
#### transport_drop(tsp) 
Drop transport client from memory

| Param           | Type                          | Description                         |
| --------------- | ----------------------------- | ----------------------------------- |
| tsp             | `transport_t *`               | Transport Client                    |

#### transport_client_new_from_url(url): transport_t * 
Generate a transport client object with a given node url

| Param           | Type                          | Description    |
| --------------- | ----------------------------- | -------------- |
| url             | `char const *`                | Node Url       |
**Returns:** A transport client wrapper to communicate with a node

#### transport_get_link_details(details, transport, link): [err_t](#Err)
Retrieved message details for a given message link

| Param           | Type                                   | Description                         |
| --------------- | -------------------------------------- | ----------------------------------- |
| details         | [`transport_details_t *`](#TransportDetails) | Resulting message details           |
| transport       | `transport_t *`                        | Transport Client                    |
| link            | `address_t const *`                    | Address link of message             |
**Returns:** Error code

### Address

#### address_from_string(addr_str): address_t * 
Create an address object form a string 

| Param           | Type                          | Description                         |
| --------------- | ----------------------------- | ----------------------------------- |
| addr_str        | `char const *`                | A string representation of link     |
**Returns:** An Address link 


#### get_address_inst_str(address): char const *
Get the string representation of the Address Application Instance

| Param           | Type                          | Description                         |
| --------------- | ----------------------------- | ----------------------------------- |
| address         | `address_t const *`           | Address link of message             | 
**Returns:** A string representation of the Address Application Instance

#### get_address_id_str(address): char const *
Get the string representation of the Address Message Identifier

| Param           | Type                          | Description                         |
| --------------- | ----------------------------- | ----------------------------------- |
| address         | `address_t const *`           | Address link of message             | 
**Returns:** A string representation of the Address Message Identifier

#### get_address_index_str(address): char const *
Get the string representation of the streams message Tangle Index

| Param           | Type                          | Description                         |
| --------------- | ----------------------------- | ----------------------------------- |
| address         | `address_t const *`           | Address link of message             | 
**Returns:** A string representation of the message Tangle Index

#### drop_address(address)
Drop an Address wrapper from memory 

| Param           | Type                          | Description                         |
| --------------- | ----------------------------- | ----------------------------------- |
| address         | `address_t const *`           | Address link of message             |


### ChannelAddress

#### get_channel_address_str(appinst): char const * 
Get the string representation of the Channel Address

| Param           | Type                          | Description                         |
| --------------- | ----------------------------- | ----------------------------------- |
| appinst         | `channel_address_t const *`   | Channel Application Instance        | 
**Returns:** A string representation of the Channel Address



### MessageLinks
Wrapper for Message containing the message link and the sequence link (if you are using multi branching)
| Param           | Type                          | Description                         |
| --------------- | ----------------------------- | ----------------------------------- |
| msg_link         | `address_t const *`          | Message link address                | 
| seq_link         | `address_t const *`          | Sequence link address               | 

#### drop_links(msg_links)
Drop a MessageLinks wrapper from memory

| Param           | Type                          | Description                         |
| --------------- | ----------------------------- | ----------------------------------- |
| msg_links       | `message_links_t`             | Message Links Wrapper               |


### UnwrappedMessage
A wrapper around a retrieved message

#### get_payload(message): packet_payloads_t
Fetch the payload from an Unwrapped Message wrapper

| Param           | Type                          | Description                         |
| --------------- | ----------------------------- | ----------------------------------- |
| message         | `unwrapped_message_t const *` | Unwrapped Message Wrapper           |
**Returns:** The PacketPayloads wrapper of the message

#### drop_unwrapped_message(message) 
Drop an Unwrapped Message wrapper from memory

| Param           | Type                          | Description                         |
| --------------- | ----------------------------- | ----------------------------------- |
| message         | `unwrapped_message_t const *` | Unwrapped Message Wrapper           |


### UnwrappedMessages
An array of `UnwrappedMessage`'s

#### get_indexed_payload(messages, index): packet_payloads_t
Fetch the payload of the provided index of the Unwrapped Messages wrapper.

| Param           | Type                           | Description                         |
| --------------- | ------------------------------ | ----------------------------------- |
| messages        | `unwrapped_messages_t const *` | Unwrapped Message Wrapper           |
| index           | `size_t`                       | Index of message in array           |
**Returns:** The PacketPayloads wrapper of the indexed message


#### drop_unwrapped_messages(messages) 
Drop an Unwrapped Messages wrapper from memory

| Param           | Type                           | Description                         |
| --------------- | ------------------------------ | ----------------------------------- |
| messages        | `unwrapped_messages_t const *` | Unwrapped Messages Wrapper          |

### PacketPayloads
Contains a `public_payload` byte array and a `masked_payload` byte array for a streams message

#### drop_payloads(payloads)
Drop a PacketPayloads wrapper from memory 

| Param           | Type                          | Description                         |
| --------------- | ----------------------------- | ----------------------------------- |
| payloads        | `packet_payloads_t`       | Packet Payloads Wrapper             |
 

### PublicKey
An Ed25519 Public Key

#### public_key_to_string(pubkey): char const *
Get a hex string representation of an Ed25519 Public Key

| Param           | Type                          | Description                         |
| --------------- | ----------------------------- | ----------------------------------- |
| pubkey          | `public_key_t *`            | Ed25519 Public Key                  |
**Returns:** Hex string representation of an Ed25519 Public Key


### NextMsgIds
A wrapper for a list mapping Public Key strings and a state cursors for expected next message ids.

#### drop_next_msg_ids(m) 
Drop a NextMsgIds wrapper from memory 

| Param           | Type                          | Description                         |
| --------------- | ----------------------------- | ----------------------------------- |
| state           | `next_msg_ids_t const *`      | A NextMsgId wrapper                 |


### UserState
A wrapper for a list mapping Public Key strings and a state cursor.

#### get_link_from_state(state, pub_key): address_t const *
Get the latest link of a specific user by their Ed25519 Public Key

| Param           | Type                          | Description                         |
| --------------- | ----------------------------- | ----------------------------------- |
| state           | `user_state_t const *`        | User State Wrapper                  |
| pubkey          | `public_key_t const *`        | Ed25519 Public Key                  |
**Returns:** Latest address link of the provided user key

#### drop_user_state(state)
Drop a User State wrapper from memory 

| Param           | Type                          | Description                         |
| --------------- | ----------------------------- | ----------------------------------- |
| state           | `user_state_t const *`        | A User State wrapper                |



### strings
#### drop_str(string)
Drop a rust allocated string from memory 

| Param           | Type                          | Description                         |
| --------------- | ----------------------------- | ----------------------------------- |
| string          | `char const *`                | A string object                     |


### PublicKeys
An array of [`PublicKey`](#PublicKey)'s

### Psk 
A 32 Byte Pre Shared Key

### PskId 
Array of 16 bytes representing the identifier of a 32 byte [`Psk`](#Psk)

#### pskid_as_str(pskid)
Drop a rust allocated string from memory 

| Param           | Type                          | Description                         |
| --------------- | ----------------------------- | ----------------------------------- |
| pskid           | `pskid_t const *`             | A Pre Shared Key Identifier         |
**Returns:** String representation of the PskId object

### PskIds 
An array of [`PskId`](#PskId)'s
