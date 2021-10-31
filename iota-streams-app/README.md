# IOTA Streams Application layer: core definitions and Channels Application.

## Streams Application

Streams Application is a message-oriented cryptographic protocol. Application defines protocol parties, their roles,
syntax and semantic of protocol messages. Messages are declared in DDML syntax and are processed according to DDML
rules. Streams Message consists of Header and Application-specific Content.

## Channels Application

Channels Application has evolved from previous versions of Streams. There are two roles: Author and Subscriber. Author
is a channel instance owner capable of proving her identity by signing messages. Subscribers in this sense are anonymous
as their public identity (ed25519 public key) is not revealed publicly. Author can share session key information
(Keyload) with a set of Subscribers. Author as well as allowed Subscribers can then interact privately and securely.

## Customization

There are a few known issues that araise in practice. Streams makes an attempt at tackling them by tweaking run-time and
compile-time parameters. If Channels Application is not suitable for your needs you can implement your own Application,
and DDML implementation as a EDSL allows you to easily wrap and unwrap messages of your Application. And when DDML is
not powerful enough, it can be extended with custom commands.
