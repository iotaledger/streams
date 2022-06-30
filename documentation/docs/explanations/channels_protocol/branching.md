---
description: Branches can be defined as any sequential grouping of messages that are linked to the announcement message
image: /img/overview/layered_overview.svg
keywords:
- explanation
- branches
- branching
- single branch
- multi branch
---
# Branching

Branches can be defined as any sequential grouping of messages that are linked to the announcement 
message. These branches will typically be generated with either a signed packet message or a keyload message for 
public and private streaming respectively. A channel can assume two different forms: 
- Single branch: a linear sequencing of messages (similar to a MAM stream) with each message linked to 
the previous one.
- Multi branch: a sequencing of messages that does not rely on sequential linking of messages.

When generating a channel, the author will decide whether the channel will use single branching or multi-
branching, this will inform the Streams instance in which way it should perform sequencing. subscribers will 
also be informed as they process the announcement message, so their instances know the appropriate 
sequencing order as well.   
