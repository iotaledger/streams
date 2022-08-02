---
description: Getting started with the official IOTA Client Library C binding.
image: /img/logo/iota_mark_light.png
keywords:
- C
- cmake
- std
- reference
---
# Getting Started

You can build a Streams API that is pulled into other languages using the C bindings. The streams instance used for the bindings is built with the `sync-client` flag to ensure a compatible client interface using the `iota.rs iota-client` crate.

## Prerequisites

Before building anything, make sure you have [`cmake`]((https://cmake.org/)) installed on your machine.

## Build the Library

1. After you have cloned the [repository](https://github.com/iotaledger/streams/), move into the C directory:

```bash
cd bindings/c
```
2. Update the [flags](#options-for-cmakelliststxt) in the [`CMakeLists.txt` file](https://github.com/iotaledger/streams/blob/develop/bindings/c/CMakeLists.txt) and run the following command to prepare the installation files:

```bash
cmake .
```
3. Build the library by running the following command:

```bash
make
```
This will generate a binary library you can include in a project. This can be either:

- `iota_streams_c_static`.
- `iota_streams_c.so` (Unix).
- `iota_streams_c.dll` (Windows).

An example of the header file can be found in [include/iota_streams/channels.h](https://github.com/iotaledger/streams/blob/develop/bindings/c/include/iota_streams/channels.h).
### Options for CMakeLlists.txt

- `NO_STD`: Enable no_std build without the iota_client. When ON, `SYNC_CLIENT` is not supported.
- `SYNC_CLIENT`: Enable sync transport via the iota_client. When OFF, it will be Bucket which you can only use for tests.
- `STATIC`: Build a static library when ON. When OFF, build a dynamic library.
- `RELEASE`: Build in release or debug mode. When ON, builds release; when OFF, build in debug mode.

To build the library, run:

```bash 
make
```

This generates a binary library that you can include in your projects. This can be either: 

- `iota_streams_c_static`
- `iota_streams_c.so` (Unix)
- `iota_streams_c.dll` (Windows)

An example of the header file can be found in `include/channels.h`.

## Starting a Channel 

Once you have [built](#build-the-library) the package, you can pull it into a script file:

```c
#include "iota_streams/channels.h"
#include <stdio.h>

int main()
{
 uint8_t multi_branching = 0;
 char seed[] = "Some unique seed";
 char const encoding[] = "utf-8";
 const size_t size = 1024;
 char const *url = "https://chrysalis-nodes.iota.org";
 
 transport_t *tsp = tsp_client_new_from_url(url);
 // Author constructor requires: (seed, encoding, payload size, multi branching, transport client)
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
}
```
