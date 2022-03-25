---
description: The Streams framework is a secure message verification and protection protocol for sending data over a given transport layer.
image: /img/overview/layered_overview.svg
keywords:
- layered overview
- high level
- low level
- stronghold
- channels
- author
- subscriber
- value transactions
- explanation
---
# Overview

The IOTA Streams framework is a secure message verification and protection protocol for sending data over a given transport layer. 

The Channels protocol is designed as a replacement for the MAM library. This was used for sending data using the Tangle as the primary transport mechanism. You can structure the channels in different ways with any arbitrary combination of publishers and subscribers (although each channel can only be hosted by a single author instance).


## Channels Protocol

The Channels protocol provides the high-level API tools necessary for you to generate authors and subscribers and interact with the Tangle. 

## Authors

A channel author is responsible for both the generation and configuration of a new channel's structure (that is, single branch vs. multi-branch). An author of a channel will also be able to set the access restrictions to branches within a channel structure, as well as accepting and managing user subscription messages. 

## Subscribers 

A channel subscriber is any user within a channel that is not the author. A subscriber can be generated independently without verification by an author. However, to write to a branch, or to process any private streams, they will be required to subscribe to the channel, and have the author accept and process that subscription. A subscriber may also use pre-shared keys as a method of interacting with a stream without going through the subscription process. 


## Branching

Branches can be defined as any sequential grouping of messages that are linked to the announcement message. These branches will be generated with either a signed packet message or a keyload message for public or private streaming, respectively. A channel can also assume two different forms: 

- Single branch: a linear sequencing of messages (similar to a MAM stream) with each message linked to the previous one.
- Multi-branch: a sequencing of messages that do not rely on sequential linking of messages.

When generating a channel, the author will decide whether the channel will use single branching or multi-branching. This will inform the Streams instance of how it should perform sequencing. Subscribers will also be informed as they process the announcement message, so their instances know the appropriate sequencing order as well.   

## Keyloads

A keyload message is an access restriction and control message that allows the author to specify who should be able to decrypt any messages that are attached and are following it. There are two ways to determine access when generating a keyload message: 

- Subscriber public keys.  
- Pre-shared keys. 

### Public Keys

During the processing of subscription messages, public keys are masked and provided to the author for storage on their instance. That author can then specify which of these users will be able to access subsequent messages by including the public key in the keyload message.

### Pre-Shared Keys

A pre-shared key is a predefined key shared between users using other means than the [subscription process](#subscribers). These keys can be used to provide access restrictions to a stream 
without the need for a subscription process. 

:::note

The security and transportation of these pre-shared keys must be ensured by the user implementations.

:::

### Sequencing

Sequencing is the methodology built within streams that allows message identifiers to be sequentially generated regardless of the shape of the channel. Messages are identified by an indexation position within the Tangle. They are generated using several pieces of collected information that includes:

- Application instances (channel identifier).
- Public keys of the publisher.
- Previous message ids (the message being linked to).
- Branch numbers (identifier for the specific branch).
- Sequencing numbers (the sequencing position of the publisher).

As messages are posted to and read from the channel, a local state for the user implementation will update with the message identifier, branch, and sequencing numbers for each publishing party. This allows user implementations to derive and search for the next message in the sequence to keep in sync. 

### Single Branch Sequencing

In a single branch implementation, sequencing the state of each user will be updated to the same state. This means that regardless of the publisher, the state of each user will update the previous message id to the new message link, and the sequencing number will be incremented by one. 

Sequence states before Msg1 is sent:
```
               Author        Sub1
Prev Msg Id     Msg0         Msg0 
Branch No.        0            0
Seq. No.          2            2       <- Users start from 2, 0 and 1 are reserved for subscriptions and announcements
```

Msg1 is then sent by the author using the author state mentioned above.

Sequence states after Msg1 is sent:
```
               Author        Sub1
Prev Msg Id     Msg1         Msg1 
Branch No.        0            0
Seq. No.          3            3     
```

:::note

We recommend that a single branch be used with only a single publisher to avoid out of sync parties from 
issuing and retrieving messages from an incorrect sequencing combination (that is, Sub1 sends a message linked to Msg1 and Sub2 
sends a message linked to that same Msg1 before seeing and registering the message from Sub1, thus forking the stream). 
Multiple publishers can be used but it is important to ensure that they do not try to send messages in parallel to 
avoid this conflict. In the future, this may be an enforced limitation on single branch implementations to remove the 
possibility altogether. 

:::

#### Multi Branch Sequencing 

In a multi-branch implementation, the sequencing state of each user will be updated independently after each message is sent. 
To track the linking of messages of individual publishers within a tree-like structure, a secondary message is 
sent in tandem with every data message. This message is called a sequencing message and it contains the necessary essence
for a user to derive the correct message id of a sequenced message. The sequencing messages are issued to an anchored 
branch generated during the creation of the channel. As a new message is generated by a user, a sequencing message is
issued to this anchored branch to give users a reference guide to the location of the issued data packet. 
