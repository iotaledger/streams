# Overview
The IOTA Streams framework is intended to be a secure message verification and protection protocol 
for sending data over a given transport layer. 

The Channels Protocol is designed as a replacement for the previously used MAM library for sending 
data using the tangle as the primary transportation mechanism. The channels themselves can be 
structured in a number of ways with any arbitrary combination of Publishers and Readers (although 
each channel can only be hosted by a single `Author` instance)


# Channels Protocol
The channels protocol provides the high level api tools necessary for Authors and Subscribers to be 
generated and interact with the tangle. 


## Authors
A channel `Author` is responsible for the generation of a new channel along with the configuration of the 
intended structure of that channel (i.e `single branch` vs `multi branch`). An `Author` of a channel will be 
able to set the access restrictions to branches within a channel structure, as well as accepting and 
managing user Subscription messages. 

## Subscribers 
A channel `Subscriber` is any user within a channel that is not the Author. A subscriber can be generated
independently without verification by an `Author`, but in order to write to a branch, or to process any 
private streams, they will be required to subscribe to the channel, and have the Author accept/process 
that subscription. A Subscriber may also use Pre-Shared Keys instead of subscription as a method of 
interacting with a stream without conducting a subscription process. 


## Branching
Branches can be defined as any sequential grouping of messages that is spawned linked to the `Announcement` 
message. These branches will typically be generated with either a `signed packet` or `keyload` message for 
public and private streaming respectively. A channel can assume two different forms: 
- `single branch` - A linear sequencing of messages (similar to a `MAM` stream) with each message linked to 
the previous one 
- `multi branch` - A sequencing of messages that does not rely on sequential linking of messages

When generating a channel, the Author will decide whether the channel will use single branching or multi-
branching, this will inform the Streams instance in which way it should perform sequencing. Subscribers will 
also be informed as they process the root message (`Announcement`) so their instances know the appropriate 
sequencing order as well.   

## Keyloads
A `Keyload` message is an access restriction/control message that allows the Author to specify who should be 
able to decrypt any messages that are attached following it. There are two ways to specify access when generating 
a `Keyload`: 
- Subscriber Public Keys  
- Pre-shared Keys 

#### Public Keys
During the processing of subscription messages, public keys are masked and provided to the Author to be stored on 
their instance. That Author can then specify which of these users will be able to access subsequent messages by 
including that public key in the `Keyload`.

#### Pre-Shared Keys (PKI's)
A predefined key shared amongst users offline. These keys can be used to provide access restrictions to a stream 
without the need for a subscription process. 

*_Note: The security and transportation of this offline key must be ensured by the user implementations_*

## Sequencing
Sequencing is the methodology built within streams to allow message identifiers to be sequentially generated regardless 
of the shape of the channel. Messages are identified by an `indexation` position within the tangle, and they are 
generated using a combination of these pieces of information:
- Application Instance (Channel Identifier)
- Public Key (Of the sender)  
- Previous message id (The message being linked to)
- Branch No (Identifier for the specific branch)
- Sequencing Number (The sequencing position of the sender)

As messages are posted to/read from the channel, a local state for the user implementation will update with the message 
identifier, branch and sequencing numbers for each publishing party. This allows user implementations to derive and 
search for the next message in the sequence to keep in sync. 

#### Single Branch Sequencing
In a single branch implementation, each user's sequencing state will be updated to the same state. This means that 
regardless of th sender, each publisher's state will update the Previous Message Id to the new message link, and the 
Sequencing Number will be incremented by one. 

Sequence states before Msg1 is sent:
```
               Author        Sub1
Prev Msg Id     Msg0         Msg0 
Branch No.        0            0
Seq. No.          2            2       <- Users start from 2, 0 and 1 are reserved for subscriptions and announcements
```

Msg1 is then sent by Author using the above stated author state...

Sequence states after Msg1 is sent:
```
               Author        Sub1
Prev Msg Id     Msg1         Msg1 
Branch No.        0            0
Seq. No.          3            3     
```

**_Note:_** *It is recommended that a single branch be used with only a single publisher to avoid out of sync parties from 
issuing/retrieving messages from an incorrect sequencing combination (i.e. Sub1 sends a message linked to Msg1 and Sub2 
sends a message linked to that same Msg1 before seeing and registering the message from Sub1, thus forking the stream). 
Multiple publishers can be used, but it is important to ensure that they do not try to send messages in parallel to 
avoid this conflict. In the future this may be an enforced limitation on single branch implementations to remove the 
possibility altogether.*

#### Multi Branch Sequencing 
In a multi branch implementation, each user's sequencing state will be updated independently after each message is sent. 
In order to track the individual publisher's linking of messages within a tree-like structure, a secondary message is 
sent in tandem with every data message. This message is called a sequencing message, and contains the essence necessary 
for a user to derive the correct message id of a sequenced message. The sequencing messages are issued to an anchored 
branch generated during the creation of the channel. As a new message is generated by a user, a sequencing message is
issued to this anchored branch to allow users a reference guide to the location of the issued data packet. 
