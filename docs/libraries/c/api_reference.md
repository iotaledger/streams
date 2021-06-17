# Iota Streams C Bindings API Reference

### Author

#### auth_new(c_seed, c_encoding, payload_length, multi_branching, transport): Author 
Generates an Author instance 

| Param           | Type                                   | Description              |
| --------------- | -------------------------------------- | ------------------------ |
| c_seed          | `*const c_char`                        | Unique user seed         |
| c_encoding      | `*const c_char`                        | Payload encoding         |
| payload_length  | `size_t`                               | Payload max length       |
| multi_branching | `uint8_t`                              | Channel Type             | 
| transport       | [`*mut TransportWrap`](#TransportWrap) | Transport Client Wrapper |
**Returns:** An Author instance for administrating a channel.

#### auth_recover(c_seed, c_ann_address, multi_branching, transport): Author 
Recover an Author instance using the announcement address link and seed.

| Param           | Type                                   | Description              |
| --------------- | -------------------------------------- | ------------------------ |
| c_seed          | `*const c_char`                        | Unique user seed         |
| c_ann_address   | [`*const Address`](#Address)           | Announcement link        |
| multi_branching | `uint8_t`                              | Channel Type             | 
| transport       | [`*mut TransportWrap`](#TransportWrap) | Transport Client Wrapper |
**Returns:** A recovered Author instance for administrating a channel.

#### auth_drop(user)
Drop an Author instance from memory.

| Param           | Type                                   | Description              |
| --------------- | -------------------------------------- | ------------------------ |
| user            | `*mut Author`                          | Author instance          |



#### auth_import(transport, bytes, bytes_size, password): Author 
Import an Author instance from an encrypted binary array

| Param           | Type                                   | Description               |
| --------------- | -------------------------------------- | ------------------------- |
| transport       | [`*mut TransportWrap`](#TransportWrap) | Transport Client Wrapper  |
| bytes           | `*const uint8_t`                       | Exported binary of author |
| bytes_size      | `size_t`                               | Binary array length       |
| password        | `*const c_char`                        | Key to decrypt binary     | 
**Returns:** A recovered Author instance for administrating a channel.

#### auth_export(user, password): *const uint8_t 
Export an Author instance as an encrypted array using a given password

| Param           | Type                | Description               |
| --------------- | ------------------- | ------------------------- |
| user            | `*mut Author`       | Author instance           |
| password        | `*cosnt char`       | Key to encrypt            | 
**Returns:** Binary array representing an encrypted state of the author.


#### auth_channel_address(user): [*const ChannelAddress](#ChannelAddress) 
Return the channel address of the channel instance. 

| Param           | Type                | Description               |
| --------------- | ------------------- | ------------------------- |
| user            | `*const Author`     | Author instance           |
**Returns:** Channel Address for user generated channel.

#### auth_is_multi_branching(user): uint8_t 
Check if a channel type is single branching or multi branching. 

| Param           | Type                | Description               |
| --------------- | ------------------- | ------------------------- |
| user            | `*const Author`     | Author instance           |
**Returns:** Uint8_t representing the channel type: 0=single branch, 1=multi branch.

#### auth_get_public_key(user): [*const PublicKey](#PublicKey) 
Retrieve the Author public key.

| Param           | Type                | Description               |
| --------------- | ------------------- | ------------------------- |
| user            | `*const Author`     | Author instance           |
**Returns:** The Author public key.


#### auth_send_announce(user): [*const Address](#Address)
Send an announcement message, initialising the channel 

| Param           | Type                | Description               |
| --------------- | ------------------- | ------------------------- |
| user            | `*mut Author`       | Author instance           |
**Returns:** The address of the announcement message.

#### auth_send_keyload_for_everyone(user, link_to): [MessageLinks](#MessageLinks)
Send a keyload message for all subscribed participants in the channel, linked to a previous message 
(usually the announcement in a multi branch).

| Param           | Type                         | Description                        |
| --------------- | ---------------------------- | ---------------------------------- |
| user            | `*mut Author`                | Author instance                    |
| link_to         | [`*const Address`](#Address) | Address of message being linked to |
**Returns:** A Message Links wrapper around the keyload message link and sequence link.

#### auth_send_keyload(user, link_to, psk_ids, sig_pks): [MessageLinks](#MessageLinks)
Send a keyload message for specified subscribers and pre shared keys in the channel, linked to a previous 
message (usually the announcement in a multi branch).

| Param           | Type                          | Description                                   |
| --------------- | ----------------------------- | --------------------------------------------- |
| user            | `*mut Author`                 | Author instance                               |
| link_to         | [`*const Address`](#Address)  | Address of message being linked to            |
| psk_ids         | [`*const PskIds`](#PskIds)    | Array of PskId's for included subscribers     |
| sig_pks         | [`*const SigPks`](#PublicKeys)| Array of Public Keys for included subscribers |
**Returns:** A Message Links wrapper around the keyload message link and sequence link.

#### auth_send_tagged_packet(user, link_to, public_payload_ptr, public_payload_ptr, masked_payload_ptr, masked_payload_size): [MessageLinks](#MessageLinks)
Send a tagged packet message linked to a previous message.

| Param              | Type                              | Description                                   |
| ------------------ | --------------------------------- | --------------------------------------------- |
| user               | `*mut Author`                     | Author instance                               |
| link_to            | [`MessageLinks`](#MessageLinks)   | Address of message being linked to            |
| public_payload_ptr | `*const_uint8_t`                  | Byte array of public payload pointer          |
| public_payload_size| `size_t`                          | Length of public payload byte array           |
| masked_payload_ptr | `*const_uint8_t`                  | Byte array of masked payload pointer          |
| masked_payload_size| `size_t`                          | Length of masked payload byte array           |
**Returns:** A MessageLinks wrapper around the tagged packet link and sequence link.

#### auth_send_signed_packet(user, link_to, public_payload_ptr, public_payload_ptr, masked_payload_ptr, masked_payload_size): [MessageLinks](#MessageLinks)
Send a signed packet message linked to a previous message.

| Param              | Type                              | Description                                   |
| ------------------ | --------------------------------- | --------------------------------------------- |
| user               | `*mut Author`                     | Author instance                               |
| link_to            | [`MessageLinks`](#MessageLinks)   | Address of message being linked to            |
| public_payload_ptr | `*const_uint8_t`                  | Byte array of public payload pointer          |
| public_payload_size| `size_t`                          | Length of public payload byte array           |
| masked_payload_ptr | `*const_uint8_t`                  | Byte array of masked payload pointer          |
| masked_payload_size| `size_t`                          | Length of masked payload byte array           |
**Returns:** A MessageLinks wrapper around the signed packet link and sequence link.

#### auth_receive_subscribe(user, link)
Process a subscription message by its link.

| Param           | Type                          | Description                         |
| --------------- | ----------------------------- | ----------------------------------- |
| user            | `*mut Author`                 | Author instance                     |
| link            | [`*const Address`](#Address)  | Address of subscription message     |

#### auth_receive_tagged_packet(user, link): [PacketPayloads](#PacketPayloads)
Receive a tagged packet by its link.

| Param           | Type                          | Description                         |
| --------------- | ----------------------------- | ----------------------------------- |
| user            | `*mut Author`                 | Author instance                     |
| link            | [`*const Address`](#Address)  | Address of tagged packet message    |
**Returns:** A Packet Payloads wrapper around the tagged packet message.

#### auth_receive_signed_packet(user, link): [PacketPayloads](#PacketPayloads)
Receive a signed packet by its link.

| Param           | Type                          | Description                         |
| --------------- | ----------------------------- | ----------------------------------- |
| user            | `*mut Author`                 | Author instance                     |
| link            | [`*const Address`](#Address)  | Address of signed packet message    |
**Returns:** A Packet Payloads wrapper around the signed packet message.

#### auth_receive_sequence(user, link): [Address](#Address)
Receive a sequence message by its link, and return the address of the sequenced message. 

| Param           | Type                          | Description                         |
| --------------- | ----------------------------- | ----------------------------------- |
| user            | `*mut Author`                 | Author instance                     |
| link            | [`*const Address`](#Address)  | Address of sequence message         |
**Returns:** The address link of the sequenced message.

#### auth_receive_msg(user, link): [*const UnwrappedMessage](#UnwrappedMessage)
Receive a message generically without knowing its type.

| Param           | Type                          | Description                          |
| --------------- | ----------------------------- | ------------------------------------ |
| user            | `*mut Author`                 | Author instance                     |
| link            | [`*const Address`](#Address)  | Address of sequence message         |
**Returns:** An Unwrapped Message wrapper around the retrieved message.

#### auth_sync_state(user): [*const UnwrappedMessage](#UnwrappedMessages)
Synchronise a publishers state prior to sending another message. Retrieves any other messages from the channel 
to ensure the user state matches all other publishers.

| Param           | Type                          | Description                         |
| --------------- | ----------------------------- | ----------------------------------- |
| user            | `*mut Author`                 | Author instance                     |
**Returns:** An Array of UnwrappedMessage wrappers around the retrieved messages.

#### auth_fetch_next_msgs(user): [*const UnwrappedMessage](#UnwrappedMessages)
Fetch the next message sent by each publisher (empty array if none are present).

| Param           | Type                          | Description                         |
| --------------- | ----------------------------- | ----------------------------------- |
| user            | `*mut Author`                 | Author instance                     |
**Returns:** An array of UnwrappedMessage wrappers around the retrieved messages.

#### auth_gen_next_msg_ids(user): [*const NextMsgIds](#NextMsgIds)
Fetch the next message sent by each publisher (empty array if none are present).

| Param           | Type                          | Description                         |
| --------------- | ----------------------------- | ----------------------------------- |
| user            | `*mut Author`                 | Author instance                     |
**Returns:** An array of NextMsgId wrappers for each publisher in the channel.

#### auth_fetch_state(user): [*const UserState](#UserState)
Fetch the current user state to see the latest links for each publisher

| Param           | Type                          | Description                         |
| --------------- | ----------------------------- | ----------------------------------- |
| user            | `*mut Author`                 | Author instance                     |



### Subscriber 

#### sub_new(c_seed, c_encoding, payload_length, transport): Subscriber 
Generates an Author instance 

| Param           | Type                                   | Description              |
| --------------- | -------------------------------------- | ------------------------ |
| c_seed          | `*const c_char`                        | Unique user seed         |
| c_encoding      | `*const c_char`                        | Payload encoding         |
| payload_length  | `size_t`                               | Payload max length       |
| transport       | [`*mut TransportWrap`](#TransportWrap) | Transport Client Wrapper |
**Returns:** A Subscriber instance for publishing to and reading from a channel.

#### sub_recover(c_seed, c_ann_address, transport): Subscriber 
Recover an Author instance using the announcement address link and seed.

| Param           | Type                                   | Description              |
| --------------- | -------------------------------------- | ------------------------ |
| c_seed          | `*const c_char`                        | Unique user seed         |
| c_ann_address   | [`*const Address`](#Address)           | Announcement link        |
| transport       | [`*mut TransportWrap`](#TransportWrap) | Transport Client Wrapper |
**Returns:** A recovered Subscriber instance for publishing to and reading from a channel.

#### sub_drop(user)
Drop a Subscriber instance from memory.

| Param           | Type                                   | Description              |
| --------------- | -------------------------------------- | ------------------------ |
| user            | `*mut Subscriber`                      | Subscriber instance      |



#### sub_import(transport, bytes, bytes_size, password): Author 
Import a Subscriber instance from an encrypted binary array

| Param           | Type                                   | Description               |
| --------------- | -------------------------------------- | ------------------------- |
| transport       | [`*mut TransportWrap`](#TransportWrap) | Transport Client Wrapper  |
| bytes           | `*const uint8_t`                       | Exported binary of author |
| bytes_size      | `size_t`                               | Binary array length       |
| password        | `*const c_char`                        | Key to decrypt binary     | 
**Returns:** A recovered Subscriber instance for publishing to and reading from a channel.

#### sub_export(user, password): *const uint8_t 
Export an Author instance as an encrypted array using a given password

| Param           | Type                | Description               |
| --------------- | ------------------- | ------------------------- |
| user            | `*mut Subscriber`   | Subscriber instance      |
| password        | `*cosnt c_char`     | Key to encrypt            | 
**Returns:** Binary array representing an encrypted state of the Subscriber.


#### sub_channel_address(user): [*const ChannelAddress](#ChannelAddress) 
Return the channel address of the channel instance. 

| Param           | Type                | Description               |
| --------------- | ------------------- | ------------------------- |
| user            | `*const Subscriber` | Subscriber instance      |
**Returns:** Channel Address for user generated channel.

#### sub_is_multi_branching(user): uint8_t 
Check if a channel type is single branching or multi branching. 

| Param           | Type                | Description               |
| --------------- | ------------------- | ------------------------- |
| user            | `*const Subscriber` | Subscriber instance      |
**Returns:** Uint8_t representing the channel type: 0=single branch, 1=multi branch.

#### sub_get_public_key(user): [*const PublicKey](#PublicKey) 
Retrieve the Subscriber public key.

| Param           | Type                | Description               |
| --------------- | ------------------- | ------------------------- |
| user            | `*const Subscriber` | Subscriber instance      |
**Returns:** The Subscriber public key.

#### sub_is_registered(user): u8 
Check if subscriber has processed an announcement message.

| Param           | Type                | Description               |
| --------------- | ------------------- | ------------------------- |
| user            | `*const Subscriber` | Subscriber instance      |
**Returns:** Uint8 representing if the Subscriber has processed an announcement. 0=false, 1=true.

#### sub_unregister(user) 
Unregister the subscriber from a channel.

| Param           | Type                | Description               |
| --------------- | ------------------- | ------------------------- |
| user            | `*mut Subscriber`   | Subscriber instance      |

#### sub_receive_announcement(user, link)
Process an announcement message by its link.

| Param           | Type                          | Description                         |
| --------------- | ----------------------------- | ----------------------------------- |
| user            | `*mut Subscriber`             | Subscriber instance                 |
| link            | [`*const Address`](#Address)  | Address of announcement message     |


#### sub_send_subscribe(user, announcement_link): [*const Address](#Address)
Send a subscription message, initialising the channel 

| Param             | Type                         | Description               |
| ----------------- | ---------------------------- | ------------------------- |
| user              | `*mut Subscribe`             | Subscriber instance       |
| announcement_link | [`*const Address`](#Address) | Announcement link         |
**Returns:** The address of the subscription message.

#### sub_send_tagged_packet(user, link_to, public_payload_ptr, public_payload_ptr, masked_payload_ptr, masked_payload_size): [MessageLinks](#MessageLinks)
Send a tagged packet message linked to a previous message.

| Param              | Type                              | Description                                   |
| ------------------ | --------------------------------- | --------------------------------------------- |
| user               | `*mut Subscriber`                 | Subscriber instance                           |
| link_to            | [`MessageLinks`](#MessageLinks)   | Address of message being linked to            |
| public_payload_ptr | `*const_uint8_t`                  | Byte array of public payload pointer          |
| public_payload_size| `size_t`                          | Length of public payload byte array           |
| masked_payload_ptr | `*const_uint8_t`                  | Byte array of masked payload pointer          |
| masked_payload_size| `size_t`                          | Length of masked payload byte array           |
**Returns:** A MessageLinks wrapper around the tagged packet link and sequence link.

#### auth_send_signed_packet(user, link_to, public_payload_ptr, public_payload_ptr, masked_payload_ptr, masked_payload_size): [MessageLinks](#MessageLinks)
Send a signed packet message linked to a previous message. 

| Param              | Type                              | Description                                   |
| ------------------ | --------------------------------- | --------------------------------------------- |
| user               | `*mut Subscriber`                 | Subscriber instance                           |
| link_to            | [`MessageLinks`](#MessageLinks)   | Address of message being linked to            |
| public_payload_ptr | `*const_uint8_t`                  | Byte array of public payload pointer          |
| public_payload_size| `size_t`                          | Length of public payload byte array           |
| masked_payload_ptr | `*const_uint8_t`                  | Byte array of masked payload pointer          |
| masked_payload_size| `size_t`                          | Length of masked payload byte array           |
**Returns:** A MessageLinks wrapper around the signed packet link and sequence link.

#### sub_receive_keyload(user, link)
Receive a keyload packet by its link.

| Param           | Type                          | Description                         |
| --------------- | ----------------------------- | ----------------------------------- |
| user            | `*mut Subscriber`             | Subscriber instance                 |
| link            | [`*const Address`](#Address)  | Address of tagged packet message    |

#### sub_receive_keyload_from_ids(user, next_msg_ids)
Receive a keyload packet by a set of next msg ids.

| Param           | Type                               | Description                         |
| --------------- | ---------------------------------- | ----------------------------------- |
| user            | `*mut Subscriber`                  | Subscriber instance                 |
| next_msg_ids    | [`*const NextMsgIds`](#NextMsgIds) | Address of tagged packet message    |


#### sub_receive_tagged_packet(user, link): [PacketPayloads](#PacketPayloads)
Receive a tagged packet by its link.

| Param           | Type                          | Description                         |
| --------------- | ----------------------------- | ----------------------------------- |
| user            | `*mut Subscriber`             | Subscriber instance                 |
| link            | [`*const Address`](#Address)  | Address of tagged packet message    |
**Returns:** A Packet Payloads wrapper around the tagged packet message.

#### sub_receive_signed_packet(user, link): [PacketPayloads](#PacketPayloads)
Receive a signed packet by its link.

| Param           | Type                          | Description                         |
| --------------- | ----------------------------- | ----------------------------------- |
| user            | `*mut Subscriber`             | Subscriber instance                 |
| link            | [`*const Address`](#Address)  | Address of signed packet message    |
**Returns:** A Packet Payloads wrapper around the signed packet message.

#### sub_receive_sequence(user, link): [Address](#Address)
Receive a sequence message by its link, and return the address of the sequenced message. 

| Param           | Type                          | Description                         |
| --------------- | ----------------------------- | ----------------------------------- |
| user            | `*mut Subscriber`             | Subscriber instance                 |
| link            | [`*const Address`](#Address)  | Address of sequence message         |
**Returns:** The address link of the sequenced message.

#### sub_receive_msg(user, link): [*const UnwrappedMessage](#UnwrappedMessage)
Receive a message generically without knowing its type.

| Param           | Type                          | Description                          |
| --------------- | ----------------------------- | ------------------------------------ |
| user            | `*mut Subscriber`             | Subscriber instance                 |
| link            | [`*const Address`](#Address)  | Address of sequence message         |
**Returns:** An Unwrapped Message wrapper around the retrieved message.

#### sub_sync_state(user): [*const UnwrappedMessage](#UnwrappedMessages)
Synchronise a publishers state prior to sending another message. Retrieves any other messages from the channel 
to ensure the user state matches all other publishers.

| Param           | Type                          | Description                         |
| --------------- | ----------------------------- | ----------------------------------- |
| user            | `*mut Subscriber`             | Subscriber instance                 |
**Returns:** An Array of UnwrappedMessage wrappers around the retrieved messages.

#### sub_fetch_next_msgs(user): [*const UnwrappedMessage](#UnwrappedMessages)
Fetch the next message sent by each publisher (empty array if none are present).

| Param           | Type                          | Description                         |
| --------------- | ----------------------------- | ----------------------------------- |
| user            | `*mut Subscriber`             | Subscriber instance                 |
**Returns:** An array of UnwrappedMessage wrappers around the retrieved messages.

#### sub_gen_next_msg_ids(user): [*const NextMsgIds](#NextMsgIds)
Fetch the next message sent by each publisher (empty array if none are present).

| Param           | Type                          | Description                         |
| --------------- | ----------------------------- | ----------------------------------- |
| user            | `*mut Subscriber`             | Subscriber instance                 |
**Returns:** An array of NextMsgId wrappers for each publisher in the channel.

#### sub_fetch_state(user): [*const UserState](#UserState)
Fetch the current user state to see the latest links for each publisher

| Param           | Type                          | Description                         |
| --------------- | ----------------------------- | ----------------------------------- |
| user            | `*mut Subscriber`             | Subscriber instance                 |


## Types

### TransportWrap 
#### tsp_new(): *mut TransportWrap
Generate a default transport client object (best for testing purposes)

| Param           | Type                          | Description                         |
| --------------- | ----------------------------- | ----------------------------------- |
**Returns:** A generic transport client wrap
 
#### tsp_drop(tsp) 
Drop transport client from memory

| Param           | Type                          | Description                         |
| --------------- | ----------------------------- | ----------------------------------- |
| tsp             | `*mut TransportWrap`          | Transport Client                    |

#### tsp_client_new_from_url(c_url): *mut TransportWrap 
Generate a transport client object with a given node url

| Param           | Type                          | Description                         |
| --------------- | ----------------------------- | ----------------------------------- |
| c_url           | `*const c_char`               | Node Url                            |
**Returns:** A transport client wrapper to communicate with a node

### Address

#### address_from_string(c_addr): *const Address 
Create an address object form a string 

| Param           | Type                          | Description                         |
| --------------- | ----------------------------- | ----------------------------------- |
| c_addr          | `*const c_char`               | A string representation of link     |
**Returns:** An Address link 


#### get_address_inst_str(address): *mut c_char
Get the string representation of the Address Application Instance

| Param           | Type                          | Description                         |
| --------------- | ----------------------------- | ----------------------------------- |
| address         | `*mut Address`                | Address link of message             | 
**Returns:** A string representation of the Address Application Instance

#### get_address_id_str(address): *mut c_char
Get the string representation of the Address Message Identifier

| Param           | Type                          | Description                         |
| --------------- | ----------------------------- | ----------------------------------- |
| address         | `*mut Address`                | Address link of message             | 
**Returns:** A string representation of the Address Message Identifier

#### get_address_index_str(address): *mut c_char
Get the string representation of the streams message Tangle Index

| Param           | Type                          | Description                         |
| --------------- | ----------------------------- | ----------------------------------- |
| address         | `*mut Address`                | Address link of message             | 
**Returns:** A string representation of the message Tangle Index

#### drop_address(address)
Drop a PacketPayloads wrapper from memory 

| Param           | Type                          | Description                         |
| --------------- | ----------------------------- | ----------------------------------- |
| address         | `*const Address`              | Address link of message             |


### ChannelAddress

#### get_channel_address_str(appinst): *const c_char 
Get the string representation of the Channel Address

| Param           | Type                          | Description                         |
| --------------- | ----------------------------- | ----------------------------------- |
| appinst         | `*const ChanelAddress`        | Channel Application Instance        | 
**Returns:** A string representation of the Channel Address



### MessageLinks
Wrapper for Message 

#### get_msg_link(msg_links): [*const Address](#Address)
Fetch the message link from a MessageLinks wrapper

| Param           | Type                          | Description                         |
| --------------- | ----------------------------- | ----------------------------------- |
| msg_links       | `*const MessageLinks`         | Message Links Wrapper               |
**Returns:** The message link address

#### get_seq_link(msg_links): [*const Address](#Address)
Fetch the sequence message link from a MessageLinks wrapper

| Param           | Type                          | Description                         |
| --------------- | ----------------------------- | ----------------------------------- |
| msg_links       | `*const MessageLinks`         | Message Links Wrapper               |
**Returns:** The sequence link address

#### drop_links(msg_links)
Drop a MessageLinks wrapper from memory

| Param           | Type                          | Description                         |
| --------------- | ----------------------------- | ----------------------------------- |
| msg_links       | `*const MessageLinks`         | Message Links Wrapper               |


### UnwrappedMessage
A wrapper around a retrieved message

#### get_payload(msg): PacketPayloads
Fetch the payload from an Unwrapped Message wrapper

| Param           | Type                          | Description                         |
| --------------- | ----------------------------- | ----------------------------------- |
| msg             | `*const UnwrappedMessage`     | Unwrapped Message Wrapper           |
**Returns:** The PacketPayloads wrapper of the message

#### drop_unwrapped_messages(ms) 
Drop an Unwrapped Message wrapper from memory

| Param           | Type                          | Description                         |
| --------------- | ----------------------------- | ----------------------------------- |
| ms              | `*const UnwrappedMessage`     | Unwrapped Message Wrapper           |


### UnwrappedMessages
An array of `UnwrappedMessage`'s

#### get_indexed_payload(msgs, index): PacketPayloads
Fetch the payload of the provided index of the Unwrapped Messages wrapper.

| Param           | Type                          | Description                         |
| --------------- | ----------------------------- | ----------------------------------- |
| msgs            | `*const UnwrappedMessages`    | Unwrapped Message Wrapper           |
| index           | `size_t`                      | Index of message in array           |
**Returns:** The PacketPayloads wrapper of the indexed message


#### drop_unwrapped_messages(ms) 
Drop an Unwrapped Messages wrapper from memory

| Param           | Type                          | Description                         |
| --------------- | ----------------------------- | ----------------------------------- |
| ms              | `*const UnwrappedMessages`    | Unwrapped Messages Wrapper          |

### PacketPayloads
Contains a `public_payload` byte array and a `masked_payload` byte array for a streams message

#### drop_payloads(payloads)
Drop a PacketPayloads wrapper from memory 

| Param           | Type                          | Description                         |
| --------------- | ----------------------------- | ----------------------------------- |
| payloads        | `*const PacketPayloads`       | Packet Payloads Wrapper             |
 

### PublicKey
An Ed25519 Public Key

#### public_key_to_string(pubkey): *const c_char
Get a hex string representation of an Ed25519 Public Key

| Param           | Type                          | Description                         |
| --------------- | ----------------------------- | ----------------------------------- |
| pubkey          | `*const PublicKey`            | Ed25519 Public Key                  |
**Returns:** Hex string representation of an Ed25519 Public Key


### NextMsgIds
A wrapper for a list mapping Public Key strings and a state cursors for expected next message ids.

#### drop_next_msg_ids(m) 
Drop a NextMsgIds wrapper from memory 

| Param           | Type                          | Description                         |
| --------------- | ----------------------------- | ----------------------------------- |
| state           | `*const NextMsgIds`           | A NextMsgId wrapper                 |


### UserState
A wrapper for a list mapping Public Key strings and a state cursor.

#### get_link_from_state(s, pub_key): *const Address
Get the latest link of a specific user by their Ed25519 Public Key

| Param           | Type                          | Description                         |
| --------------- | ----------------------------- | ----------------------------------- |
| s               | `*const UserState`            | User State Wrapper                  |
| pubkey          | `*const PublicKey`            | Ed25519 Public Key                  |
**Returns:** Latest address link of the provided user key

#### drop_user_state(s)
Drop a User State wrapper from memory 

| Param           | Type                          | Description                         |
| --------------- | ----------------------------- | ----------------------------------- |
| state           | `*const UserState`            | A User State wrapper                |



### strings
#### drop_str(string)
Drop a PacketPayloads wrapper from memory 

| Param           | Type                          | Description                         |
| --------------- | ----------------------------- | ----------------------------------- |
| string          | `*const c_char`               | A string object                     |


### PublicKeys
An array of [`PublicKey`](#PublicKey)'s

### Psk 
A 32 Byte Pre Shared Key

### PskId 
Array of 16 bytes representing the identifier of a 32 byte [`Psk`](#Psk)

### PskIds 
An array of [`PskId`](#PskId)'s
