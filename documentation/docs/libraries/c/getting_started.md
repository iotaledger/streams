---
description: Getting started with the official IOTA Client Library C binding.
image: /img/logo/iota_mark_light.png
keywords:
- C
- cmake
- std
---
# Getting Started
The C bindings allow for you to build a Streams API which can be pulled into other languages. 
The streams instance underlying the bindings is built with the `sync-client` flag to 
ensure a compatible client interface using the `iota.rs iota-client` crate. 

Before building anything you'll need to make sure you have `cmake` installed on your 
machine.

To build the library, first make sure you're in the c directory:
```
cd bindings/c
``` 
Update the flags in the `CMakeLists.txt` and run ```cmake .``` to 
prepare the installation files. 

#### Options for CMakeLlists.txt
- `NO_STD`: Enable no_std build, without iota_client (when ON, `SYNC_CLIENT` isnt supported)
- `SYNC_CLIENT`: Enable sync transport via iota_client, otherwise it's going to be Bucket which can only be used for tests
- `STATIC`: Build static library when ON, otherwise dynamic library
- `RELEASE`: Build in release or debug mode (when ON, builds release, when OFF, build debug)

To build the library run:
```bash 
make
```

This generates a binary library to be included into a project. This can be either: 
- `iota_streams_c_static`
- `iota_streams_c.so` (Unix)
- `iota_streams_c.dll` (Windows)

An example of the header file can be found in `include/channels.h`.

### Starting a Channel 
Once the package has been built, you can pull it into a script file like so: 
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
