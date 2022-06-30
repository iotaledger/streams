---
description: "The Streams framework is intended to be a secure message verification and protection protocol 
for sending data over a given transport layer"
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
---
# Channels Protocol

The IOTA Streams framework is intended to be a secure message verification and protection protocol 
for sending data over a given transport layer. 

The Channels protocol is designed as a replacement for the previously used MAM library for sending 
data using the Tangle as the primary transportation mechanism. The channels themselves can be 
structured in a number of ways with any arbitrary combination of publishers and subscribers (although 
each channel can only be hosted by a single author instance)

The Channels protocol provides the high level API tools necessary for authors and subscribers to be 
generated and interact with the Tangle. 

