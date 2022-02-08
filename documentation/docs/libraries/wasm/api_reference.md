# API Reference

## Contents 
The API is spread out across three categories: 
- [Author](#Author)
- [Subscriber](#Subscriber)
- [Types](#Types)


## Author
Main user implementation of a Channel. Generates the channel, processes subscriptions 
and manages them. It can also send and fetch messages.

#### new(seed, options, channel_type): Author 

Generates an Author instance 

| Param           | Type                | Description        |
| --------------- | ------------------- | ------------------ |
| seed            | `string`            | Unique user seed   |
| options         | `SendOptions`       | Options for Client |
| implementation  | [`ChannelType`](#ChannelType) | Channel Type    | 

**Returns:** An Author instance for administrating a channel.


#### from_client(client, seed, implementation): Author 

Create an Author instance from a client

| Param           | Type                | Description        |
| --------------- | ------------------- | ------------------ |
| client          | [`Client`](#Client) | A Client Instance  |
| seed            | `string`            | Unique user seed   |
| implementation  | [`ChannelType`](#ChannelType) | Channel Type    |

**Returns:** An Author instance for administrating a channel.


#### import(client, bytes, password): Author 

Import an Author instance from an encrypted binary array

| Param           | Type                | Description               |
| --------------- | ------------------- | ------------------------- |
| client          | [`Client`](#Client) | A Client Instance         |
| bytes           | `Uint8Array`        | Exported binary of author |
| password        | `string`            | Key to decrypt binary     | 

**Returns:** A recovered Author instance for administrating a channel.


#### export(password): Uint8Array 

Export an Author instance as an encrypted array using a given password

| Param           | Type                | Description               |
| --------------- | ------------------- | ------------------------- |
| password        | `string`            | Key to encrypt            | 

**Returns:** Binary array representing an encrypted state of the author.


#### recover(seed, ann_address, implementation, options): Author

Recover an Author instance from scratch using the known startup configurations

| Param           | Type                | Description               |
| --------------- | ------------------- | ------------------------- |
| seed            | `string`            | Unique user seed          |
| ann_address     | [`Address`](#Address) | Announcement message address for validation | 
| implementation  | [`ChannelType`](#ChannelType) | Channel Type    | 
| options         | `SendOptions`       | Options for Client        |

**Returns:** A recovered Author instance for administrating a channel.


#### clone(): Author 

Generate a copy of the Author instance for consumption by asynchronous functions

| Param           | Type                | Description               |
| --------------- | ------------------- | ------------------------- |

**Returns:** A consumable Author instance for functions.


#### channel_address(): string 

Return the channel address of the channel instance. 

| Param           | Type                | Description               |
| --------------- | ------------------- | ------------------------- |

**Returns:** Channel Address for user generated channel.


#### announcementLink(): string

Return the announcement link of the channel instance.

| Param           | Type                | Description               |
| --------------- | ------------------- | ------------------------- |

**Returns:** Announcement Address for user generated channel.


#### is_multi_branching(): bool 

Check if a channel type is single branching or multi branching. 

| Param           | Type                | Description               |
| --------------- | ------------------- | ------------------------- |

**Returns:** Boolean representing the channel type: false=single branch, true=multi branch.


#### get_public_key(): string 

Retrieve the Author public key.

| Param           | Type                | Description               |
| --------------- | ------------------- | ------------------------- |

**Returns:** The Author public key in hex representation.


#### fetch_state(): Array&lt;[UserState](#UserState)>

Retrieve the currently known publisher states for the channel.

| Param           | Type                | Description               |
| --------------- | ------------------- | ------------------------- |

**Returns:** An array of user state objects representing the currently known state of all publishers in the channel.

:::info

The following functions require author.clone() to use, as they consume the instance 

:::

#### _async -_ send_announce(): [UserResponse](#UserResponse)

Send an announcement message, initialising the channel 

| Param           | Type                | Description               |
| --------------- | ------------------- | ------------------------- |

**Returns:** A User Response wrapper around the announcement message.


#### _async -_ send_keyload_for_everyone(link): [UserResponse](#UserResponse)

Send a keyload message for all subscribed participants in the channel, linked to a previous message 
(usually the announcement in a multi branch).

| Param           | Type                  | Description                        |
| --------------- | --------------------- | ---------------------------------- |
| link            | [`address`](#Address) | Address of message being linked to |

**Returns:** A User Response wrapper around the keyload message.


#### _async -_ send_keyload(link, psk_ids, sig_pks): [UserResponse](#UserResponse)

Send a keyload message for specified subscribers and pre shared keys in the channel, linked to a previous 
message (usually the announcement in a multi branch).

| Param           | Type                          | Description                                   |
| --------------- | ----------------------------- | --------------------------------------------- |
| link            | [`address`](#Address)         | Address of message being linked to            |
| psk_ids         | [`PskIds`](#PskIds)           | PskIds instance                               |
| sig_pks         | [`PublicKeys`](#PublicKeys)   | PublicKeys instance                           |

**Returns:** A User Response wrapper around the keyload message.


#### _async -_ send_tagged_packet(link, public_payload, masked_payload): [UserResponse](#UserResponse)

Send a tagged packet message linked to a previous message (usually the announcement in a multi branch).

| Param           | Type                          | Description                                   |
| --------------- | ----------------------------- | --------------------------------------------- |
| link            | [`address`](#Address)         | Address of message being linked to            |
| public_payload  | `Uint8Array`                  | Byte array of public payload for message      |
| masked_payload  | `Uint8Array`                  | Byte array of masked payload for message      |

**Returns:** A User Response wrapper around the tagged packet message.


#### _async -_ send_signed_packet(link, public_payload, masked_payload): [UserResponse](#UserResponse)

Send a signed packet message linked to a previous message (usually the announcement in a multi branch).

| Param           | Type                          | Description                                   |
| --------------- | ----------------------------- | --------------------------------------------- |
| link            | [`address`](#Address)         | Address of message being linked to            |
| public_payload  | `Uint8Array`                  | Byte array of public payload for message      |
| masked_payload  | `Uint8Array`                  | Byte array of masked payload for message      |

**Returns:** A User Response wrapper around the signed packet message.


#### _async -_ receive_subscribe(link)

Process a subscription message by its link.

| Param           | Type                          | Description                         |
| --------------- | ----------------------------- | ----------------------------------- |
| link            | [`address`](#Address)         | Address of subscription message     |


#### _async -_ receive_unsubscribe(link)

Process an unsubscription message by its link.

| Param           | Type                          | Description                         |
| --------------- | ----------------------------- | ----------------------------------- |
| link            | [`address`](#Address)         | Address of unsubscription message   |


#### _async -_ receive_tagged_packet(link): [UserResponse](#UserResponse)

Receive a tagged packet by its link.

| Param           | Type                          | Description                         |
| --------------- | ----------------------------- | ----------------------------------- |
| link            | [`address`](#Address)         | Address of tagged packet message    |

**Returns:** A User Response wrapper around the tagged packet message.


#### _async -_ receive_signed_packet(link): [UserResponse](#UserResponse)

Receive a signed packet by its link.

| Param           | Type                          | Description                         |
| --------------- | ----------------------------- | ----------------------------------- |
| link            | [`address`](#Address)         | Address of signed packet message    |

**Returns:** A User Response wrapper around the signed packet message.


#### _async -_ receive_sequence(link): [Address](#Address)

Receive a sequence message by its link, and return the address of the sequenced message. 

| Param           | Type                          | Description                         |
| --------------- | ----------------------------- | ----------------------------------- |
| link            | [`address`](#Address)         | Address of tagged packet message    |

**Returns:** The address link of the sequenced message.


#### _async -_ receive_msg(link): [UserResponse](#UserResponse)

Receive a message generically without knowing its type.

| Param           | Type                          | Description                          |
| --------------- | ----------------------------- | ------------------------------------ |
| link            | [`address`](#Address)         | Address of the message to be fetched |

**Returns:** A User Response wrapper around the retrieved message.


#### _async -_ receive_msg_by_sequence_number(anchor_link, msg_num): [UserResponse](#UserResponse)

Receive a message by its msg number in an anchored single depth channel.

| Param           | Type                          | Description                          |
| --------------- | ----------------------------- | ------------------------------------ |
| anchor_link     | [`address`](#Address)         | Anchor message link for the channel  |
| msg_num         | `number`                     | Number of the message being retrieved|

**Returns:** A User Response wrapper around the retrieved message.


#### _async -_ sync_state()

Synchronise a publishers state prior to sending another message. Retrieves any other messages from the channel 
to ensure the user state matches all other publishers.

| Param           | Type                          | Description                         |
| --------------- | ----------------------------- | ----------------------------------- |


#### _async -_ fetch_next_msgs(): Array&lt;[UserResponse](#UserResponse)>
Fetch all the next messages pending to be received by the user (empty array if none are present).

| Param           | Type                          | Description                         |
| --------------- | ----------------------------- | ----------------------------------- |

**Returns:** An array of User Response wrappers around the retrieved messages.


#### _async -_ fetch_prev_msg(link): [UserResponse](#UserResponse)

Fetch the previous message sent before the provided message link.

| Param           | Type                          | Description                         |
| --------------- | ----------------------------- | ----------------------------------- |
| link            | [`address`](#Address)         | Address off message to begin fetching from |

**Returns:** A User Response wrapper around the retrieved message.


#### _async -_ fetch_prev_msgs(link, max): Array&lt;[UserResponse](#UserResponse)>

Fetch a defined number of previous messages in a channel.

| Param           | Type                          | Description                         |
| --------------- | ----------------------------- | ----------------------------------- |
| link            | [`address`](#Address)         | Address off message to begin fetching from |
| max             | `number`                      | Max number of messages to fetch     |

**Returns:** An array of User Response wrappers around the retrieved messages.

#### store_psk(psk): String 

Store a Pre Shared Key (Psk) and retrieve the Pre Shared Key Id (PskId) for use in keyload messages 
| Param           | Type                          | Description                         |
| --------------- | ----------------------------- | ----------------------------------- |
| psk             | String                        | Pre shared key in string format     |


**Returns:** A PskId String representing the Psk in store.


#### remove_psk(pskid)

Removes a Pre Shared Key (Psk) from the Author instance using a Pre Shared Key Id (PskId)

| Param           | Type                                   | Description              |
| --------------- | -------------------------------------- | ------------------------ |
| pskid           | String                                 | PskId string representing the Psk in store |


#### store_new_subscriber(pk)

Store the ed25519 Public Key identifier of a predefined subscriber into the Author instance

| Param           | Type                                   | Description              |
| --------------- | -------------------------------------- | ------------------------ |
| pk              | String                                  | Public Key string of Subscriber |


#### auth_remove_subscriber(pk)

Removes a Subscriber from the Author instance using their ed25519 Public Key

| Param           | Type                                   | Description              |
| --------------- | -------------------------------------- | ------------------------ |
| pk              | String                                 | Public Key string of Subscriber |


#### reset_state()

Reset the mapping of known publisher states for the channel for retrieval of messages from scratch.

| Param           | Type                | Description               |
| --------------- | ------------------- | ------------------------- |



## Subscriber
Additional user implementations of a Channel. Can publish and read from public branches, and 
branches that have been restricted by keyload messages that contain their public key. 

#### new(seed, options): Subscriber 

Generates a Subscriber instance 

| Param           | Type                | Description        |
| --------------- | ------------------- | ------------------ |
| seed            | `string`            | Unique user seed   |
| options         | `SendOptions`       | Options for Client |

**Returns:** A Subscriber instance.


#### from_client(client, seed): Subscriber 

Create a Subscriber instance from a client

| Param           | Type                | Description        |
| --------------- | ------------------- | ------------------ |
| client          | [`Client`](#Client) | A Client Instance  |
| seed            | `string`            | Unique user seed   |

**Returns:** A Subscriber instance.


#### import(client, bytes, password): Subscriber 

Import a Subscriber instance from an encrypted binary array

| Param           | Type                | Description               |
| --------------- | ------------------- | ------------------------- |
| client          | [`Client`](#Client) | A Client Instance         |
| bytes           | `Uint8Array`        | Exported binary of author |
| password        | `string`            | Key to decrypt binary     | 

**Returns:** A recovered Subscriber instance.


#### export(password): Uint8Array 

Export a Subscriber instance as an encrypted array using a given password

| Param           | Type                | Description               |
| --------------- | ------------------- | ------------------------- |
| password        | `string`            | Key to encrypt            | 

**Returns:** Binary array representing an encrypted state of the subscriber.


#### clone(): Subscriber 

Generate a copy of the Subscriber instance for consumption by asynchronous functions

| Param           | Type                | Description               |
| --------------- | ------------------- | ------------------------- |

**Returns:** A consumable Subscriber instance for functions.


#### channel_address(): string 

Return the channel address of the channel instance. 

| Param           | Type                | Description               |
| --------------- | ------------------- | ------------------------- |

**Returns:** Channel Address for user generated channel.


#### announcementLink(): string

Return the announcement link of the channel instance.

| Param           | Type                | Description               |
| --------------- | ------------------- | ------------------------- |

**Returns:** Announcement Address for user generated channel.


#### is_multi_branching(): bool 

Check if a channel type is single branching or multi branching. 

| Param           | Type                | Description               |
| --------------- | ------------------- | ------------------------- |

**Returns:** Boolean representing the channel type: false=single branch, true=multi branch.


#### get_public_key(): string 

Retrieve the Subscriber public key.

| Param           | Type                | Description               |
| --------------- | ------------------- | ------------------------- |

**Returns:** The Subscriber public key in hex representation.


#### author_public_key(): string 

Retrieve the Author public key. Errors if no channel is registered.

| Param           | Type                | Description               |
| --------------- | ------------------- | ------------------------- |

**Returns:** The Subscriber public key in hex representation.


#### is_registered(): bool 

Check if the subscriber instance has processed a channel announcement. 

| Param           | Type                | Description               |
| --------------- | ------------------- | ------------------------- |

**Returns:** Boolean representing if the subscriber instance has processed a channel announcement correctly.


#### unregister() 

Unregister a subscriber instance from a channel. 

| Param           | Type                | Description               |
| --------------- | ------------------- | ------------------------- |


#### fetch_state(): Array&lt;[UserState](#UserState)>

Retrieve the currently known publisher states for the channel.

| Param           | Type                | Description               |
| --------------- | ------------------- | ------------------------- |

**Returns:** An array of user state objects representing the currently known state of all publishers in the channel.

:::info

The following functions require subscriber.clone() to use, as they consume the instance

:::

#### _async -_ send_subscribe(link): [UserResponse](#UserResponse)

Send a subscription message attached to an announcement message link. 

| Param           | Type                | Description                       |
| --------------- | ------------------- | --------------------------------- |
| link            | [`address`](#Address) | Address of announcement message |

**Returns:** A User Response wrapper around the subscribe message.


#### _async -_ send_unsubscribe(link): [UserResponse](#UserResponse)

Send an unsubscription message attached to the user subscription message link.

| Param           | Type                | Description                       |
| --------------- | ------------------- | --------------------------------- |
| link            | [`address`](#Address) | Address of subscription message |

**Returns:** A User Response wrapper around the unsubscribe message.


#### _async -_ send_tagged_packet(link, public_payload, masked_payload): [UserResponse](#UserResponse)

Send a tagged packet message linked to a previous message (usually the announcement in a multi branch).

| Param           | Type                          | Description                                   |
| --------------- | ----------------------------- | --------------------------------------------- |
| link            | [`address`](#Address)         | Address of message being linked to            |
| public_payload  | `Uint8Array`                  | Byte array of public payload for message      |
| masked_payload  | `Uint8Array`                  | Byte array of masked payload for message      |

**Returns:** A User Response wrapper around the tagged packet message.

#### _async -_ send_signed_packet(link, public_payload, masked_payload): [UserResponse](#UserResponse)

Send a signed packet message linked to a previous message (usually the announcement in a multi branch).

| Param           | Type                          | Description                                   |
| --------------- | ----------------------------- | --------------------------------------------- |
| link            | [`address`](#Address)         | Address of message being linked to            |
| public_payload  | `Uint8Array`                  | Byte array of public payload for message      |
| masked_payload  | `Uint8Array`                  | Byte array of masked payload for message      |

**Returns:** A User Response wrapper around the signed packet message.


#### _async -_ receive_announcement(link)

Process an announcement message and register the channel.

| Param           | Type                          | Description                         |
| --------------- | ----------------------------- | ----------------------------------- |
| link            | [`address`](#Address)         | Address of the announcement message |


#### _async -_ receive_keyload(link): bool

Receive a keyload by its link and return whether the subscriber has access beyond it or not.

| Param           | Type                          | Description                         |
| --------------- | ----------------------------- | ----------------------------------- |
| link            | [`address`](#Address)         | Address of tagged packet message    |

**Returns:** Boolean representing access to the branch.


#### _async -_ receive_tagged_packet(link): [UserResponse](#UserResponse)

Receive a tagged packet by its link.

| Param           | Type                          | Description                         |
| --------------- | ----------------------------- | ----------------------------------- |
| link            | [`address`](#Address)         | Address of tagged packet message    |

**Returns:** A User Response wrapper around the tagged packet message.


#### _async -_ receive_signed_packet(link): [UserResponse](#UserResponse)

Receive a signed packet by its link.

| Param           | Type                          | Description                         |
| --------------- | ----------------------------- | ----------------------------------- |
| link            | [`address`](#Address)         | Address of signed packet message    |

**Returns:** A User Response wrapper around the signed packet message.


#### _async -_ receive_sequence(link): [Address](#Address)

Receive a sequence message by its link, and return the address of the sequenced message. 

| Param           | Type                          | Description                         |
| --------------- | ----------------------------- | ----------------------------------- |
| link            | [`address`](#Address)         | Address of tagged packet message    |

**Returns:** The address link of the sequenced message.


#### _async -_ receive_msg(link): [UserResponse](#UserResponse)

Receive a message generically without knowing its type.

| Param           | Type                          | Description                          |
| --------------- | ----------------------------- | ------------------------------------ |
| link            | [`address`](#Address)         | Address of the message to be fetched |

**Returns:** A User Response wrapper around the retrieved message.


#### _async -_ receive_msg_by_sequence_number(anchor_link, msg_num): [UserResponse](#UserResponse)

Receive a message by its msg number in an anchored single depth channel.

| Param           | Type                          | Description                          |
| --------------- | ----------------------------- | ------------------------------------ |
| anchor_link     | [`address`](#Address)         | Anchor message link for the channel  |
| msg_num         | `number`                     | Number of the message being retrieved|

**Returns:** A User Response wrapper around the retrieved message.


#### _async -_ sync_state()

Synchronise a publishers state prior to sending another message. Retrieves any other messages from the channel 
to ensure the user state matches all other publishers.

| Param           | Type                          | Description                         |
| --------------- | ----------------------------- | ----------------------------------- |


#### _async -_ fetch_next_msgs(): Array&lt;[UserResponse](#UserResponse)>

Fetch all the next messages pending to be received by the user (empty array if none are present).

| Param           | Type                          | Description                         |
| --------------- | ----------------------------- | ----------------------------------- |

**Returns:** An array of User Response wrappers around the retrieved messages.


#### _async -_ fetch_prev_msg(link): [UserResponse](#UserResponse)

Fetch the previous message sent before the provided message link.

| Param           | Type                          | Description                         |
| --------------- | ----------------------------- | ----------------------------------- |
| link            | [`address`](#Address)         | Address off message to begin fetching from |

**Returns:** A User Response wrapper around the retrieved message.


#### _async -_ fetch_prev_msgs(link, max): Array&lt;[UserResponse](#UserResponse)>

Fetch a defined number of previous messages in a channel.

| Param           | Type                          | Description                         |
| --------------- | ----------------------------- | ----------------------------------- |
| link            | [`address`](#Address)         | Address off message to begin fetching from |
| max             | `number`                      | Max number of messages to fetch     |

**Returns:** An array of User Response wrappers around the retrieved messages.


#### store_psk(psk): String 

Store a Pre Shared Key (Psk) and retrieve the Pre Shared Key Id (PskId) for use in keyload messages 
| Param           | Type                          | Description                         |
| --------------- | ----------------------------- | ----------------------------------- |
| psk             | String                        | Pre shared key in string format     |

**Returns:** A PskId String representing the Psk in store.


#### remove_psk(pskid)

Removes a Pre Shared Key (Psk) from the Author instance using a Pre Shared Key Id (PskId)

| Param           | Type                                   | Description              |
| --------------- | -------------------------------------- | ------------------------ |
| pskid           | String                                 | PskId string representing the Psk in store |


#### reset_state()

Reset the mapping of known publisher states for the channel for retrieval of messages from scratch.

| Param           | Type                | Description               |
| --------------- | ------------------- | ------------------------- |


## Types
Generic Types and Primitives used in Wasm API:
- [Client](#client)
- [SendOptions](#sendoptions)
- [UserResponse](#userresponse)
- [Address](#address)
- [Message](#message)
- [NextMsgId](#nextmsgid)
- [Cursor](#cursor)
- [UserState](#userstate)

### Client 

Transport client for interacting with an Iota node.

#### new(node, options): Client

| Param           | Type                | Description        |
| --------------- | ------------------- | ------------------ |
| node            | `string`            | A node URL         |
| options         | `SendOptions`       | Options for Client |

**Returns:** A client instance.

### SendOptions

Options for a transport client

#### new(url, depth, local_pow, threads): SendOptions

Create a new set of Send Options for the client

| Param     | Type                 | Description                  |
| --------- | -------------------- | ---------------------------- |
| url       | `string`             | A node URL                   |
| local_pow | `bool`               | Perform pow locally          |

**Returns:** Send Options for a client instance.

### UserResponse

Response structure containing the details of a sent or retrieved message 

#### new(link, seq_link, message): UserResponse

Create a new User Response from the return of the rust api for sending and receiving messages.

| Param     | Type                  | Description                                  |
| --------- | --------------------- | -------------------------------------------- |
| link      | [`Address`](#Address) | Address link of message                      |
| seq_link  | [`Address`](#Address) | Sequence Address Link (can be undefined)     |
| message   | [`Message`](#Message) | Sent or retrieved message (can be undefined) |

**Returns:** User Response containing links and message.


#### from_strings(link, seq_link, message): UserResponse

Create a new User Response from the return of the rust api for sending and receiving messages, 
using strings for the link and seq_link inputs.

| Param     | Type                  | Description                                  |
| --------- | --------------------- | -------------------------------------------- |
| link      | `string`              | Address string of message                    |
| seq_link  | `string`              | Sequence Address string (can be undefined)   |
| message   | [`Message`](#Message) | Sent or retrieved message (can be undefined) |

**Returns:** User Response containing links and message.


#### copy(): UserResponse

Create a copy of the User Response

| Param     | Type                  | Description                                  |
| --------- | --------------------- | -------------------------------------------- |

**Returns:** A copy of the User Response.


#### get_seq_link(): [Address](#Address)

Fetch the sequence link of the retrieved or sent message (Default if there is none).

| Param     | Type                  | Description                                  |
| --------- | --------------------- | -------------------------------------------- |

**Returns:** The link for the retrieved or sent message.


#### get_message(): [Message](#Message)

Fetch the retrieved or sent message (Default if there is none).

| Param     | Type                  | Description                                  |
| --------- | --------------------- | -------------------------------------------- |

**Returns:** The retrieved or sent message.

### Address

Streams Address containing the Application Instance and Message Id 

#### set_addr_id(addr_id)

| Param     | Type                  | Description                                  |
| --------- | --------------------- | -------------------------------------------- |
| addr_id   | `string`              | Application instance of the channel          |


#### addr_id(): string

| Param     | Type                  | Description                                  |
| --------- | --------------------- | -------------------------------------------- |

**Returns:** The Channel Identifier/Application Instance of the Address


#### set_msg_id(msg_id)

| Param     | Type                  | Description                                  |
| --------- | --------------------- | -------------------------------------------- |
| msg_id    | `string`              | Message Identifier of the message itself     |


#### msg_id(): string

| Param     | Type                  | Description                                  |
| --------- | --------------------- | -------------------------------------------- |

**Returns:** The Message Identifier of the Address


#### from_string(address): Address

Make an Address object from a string representation
 
| Param     | Type                  | Description                                  |
| --------- | --------------------- | -------------------------------------------- |
| address   | `string`              | String representation of an Address          |

**Returns:** An Address object


#### to_string(): string

Return a string representation of an Address object

| Param     | Type                  | Description                                  |
| --------- | --------------------- | -------------------------------------------- |

**Returns:** String representation of an Address

### Message 

A wrapper for a Rust Streams Message

#### default(): Message 

Generate a default message object

| Param     | Type                  | Description                                  |
| --------- | --------------------- | -------------------------------------------- |

**Returns:** A default Message object


#### new(pk, public_payload, masked_payload): Message

Make a Message object from the optional pk and the public and masked payloads
 
| Param          | Type                 | Description                          |
| -------------- | -------------------- | ------------------------------------ |
| pk             | `string / undefined` | Optional public key for message      |
| public_payload | `Uint8Array`         | Public payload bytes                 |
| masked_payload | `Uint8Array`         | Masked payload bytes                 |

**Returns:** A Message wrapper object


#### get_public_key(): string

Fetch the public key of the Message sender (default if none is presented)

| Param     | Type                  | Description                                  |
| --------- | --------------------- | -------------------------------------------- |

**Returns:** Public key in hex representation of the sender of the message 


#### get_public_payload(): Uint8Array

Fetch the public payload of the Message sender

| Param     | Type                  | Description                                  |
| --------- | --------------------- | -------------------------------------------- |

**Returns:** Public payload byte array 


#### get_masked_payload(): Uint8Array

Fetch the masked payload of the Message sender

| Param     | Type                  | Description                                  |
| --------- | --------------------- | -------------------------------------------- |

**Returns:** Masked payload byte array 

### NextMsgId 

A wrapper for a Rust NextMsgId structure

#### new(identifier, msgid): NextMsgId

Make a NextMsgId object from the identifier and expected next message address
 
| Param          | Type                  | Description                          |
| -------------- | --------------------- | ------------------------------------ |
| identifier     | `string`              | Identifier for expected message      |
| msgid          | [`Address`](#Address) | Address of expected next message     |

**Returns:** A NextMsgId wrapper object


#### get_identifier(): string

Fetch the identifier of the Message sender

| Param     | Type                  | Description                                  |
| --------- | --------------------- | -------------------------------------------- |

**Returns:** Identifier in hex representation of the sender of the message 

### PskIds

An array of PskIds representing the Pre Shared Keys that are used in keyload messages.

#### new(): PskIds 

Generate a new array of PskIds

| Param     | Type                  | Description                                  |
| --------- | --------------------- | -------------------------------------------- |

**Returns:** Empty array for PskIds to be added to


#### add(pskid) 

Add a pskid 

| Param     | Type                  | Description                                    |
| --------- | --------------------- | ---------------------------------------------- | 
| pskid     | `string`              | PskId string representation [must be 32 bytes] |


#### get_ids(): Array&lt;string>

Fetch PskIds in string formatting

| Param     | Type                  | Description                                  |
| --------- | --------------------- | -------------------------------------------- |

**Returns:** Array of PskIds in string formatting

### PublicKeys

An array of PublicKeys representing a set of users.

#### new(): PublicKeys 

Generate a new array of PublicKeys

| Param     | Type                  | Description                                  |
| --------- | --------------------- | -------------------------------------------- |

**Returns:** Empty array for PublicKeys to be added to


#### add(pk) 

Add a public key string

| Param     | Type                  | Description                                    |
| --------- | --------------------- | ---------------------------------------------- | 
| pk        | `string`              | Public Key string representation               |


#### get_pks(): Array&lt;string>

Fetch Public Keys in string formatting

| Param     | Type                  | Description                                  |
| --------- | --------------------- | -------------------------------------------- |

**Returns:** Array of Public Keys in string formatting

### Cursor

The publishing state of a particular publisher (The latest sequenced message known for that publisher). This includes:
- The latest published message link
- The sequence state number of the publisher
- A branch number for that latest posted message 

### UserState

A wrapper around a publisher state. Includes the identifier and [cursor](#Cursor) of the publisher

#### get_identifier()

Get the public key of the user from the state

| Param     | Type                  | Description                                  |
| --------- | --------------------- | -------------------------------------------- |

**Returns:** Identifier of publisher in hex formatting


#### get_link() 

Get the link from the internal cursor object 

| Param     | Type                  | Description                                  |
| --------- | --------------------- | -------------------------------------------- |

**Returns:** The latest published message link 


#### get_seq_no()

Get the sequence state number from the internal cursor object 

| Param     | Type                  | Description                                  |
| --------- | --------------------- | -------------------------------------------- |

**Returns:** The latest sequence state number of the publisher 


#### get_branch_no()

Get the branch state number from the internal cursor object

| Param     | Type                  | Description                                  |
| --------- | --------------------- | -------------------------------------------- |

**Returns:** The latest branch state number of the publisher 
