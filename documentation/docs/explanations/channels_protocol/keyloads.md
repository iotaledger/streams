---
description: A keyload message is an access restriction and control message that allows the author to specify who should be able to decrypt any messages that are attached following it.
image: /img/overview/layered_overview.svg
keywords:
- explanation
- keyloads
- public keys
- pre
- access restrictions
- message
---
# Keyloads

A keyload message is an access restriction and control message that allows the author to specify who should be
able to decrypt any messages that are attached following it. There are two ways to specify access when generating
a keyload message:
- Subscriber public keys
- Pre-shared keys

### Public Keys

During the processing of subscription messages, public keys are masked and provided to the author to be stored on
their instance. That author can then specify which of these users will be able to access subsequent messages by
including that public key in the keyload message.

### Pre-Shared Keys

A predefined key shared amongst users by other means then the subscription process above. These keys can be used to provide access restrictions to a stream
without the need for a subscription process.

:::note

The security and transportation of these pre-shared keys must be ensured by the user implementations.

:::
