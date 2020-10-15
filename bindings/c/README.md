# IOTA Streams Application layer: C bindings

## Instructions

Check out `CMakeLists.txt` and change the 3 options to your preference:
`NO_STD`: Enable no_std build, without iota_client (when ON, `SYNC_CLIENT` isnt supported)
`SYNC_CLIENT`: Enable sync transport via iota_client, otherwise goes to async
`STATIC`: Build static library when ON, otherwise dynamic library

Edit your author and subscriber seeds in `main.c`

run `cmake .` in this folder

Then run `make` to build the rust code.

A binary will be generated which you can run depending on your STATIC setting
ON:  `iota_streams_c_static`
OFF: `libiota_streams_c.so`(Unix), `iota_streams_c.dll`(Windows) and the executable `iota_streams_c`

You can then run the static build or the dynamic executable. Keep in mind that by default the code points to a node on `http://localhost:14265`.
If this node doesnt exist, we will exit with an error immediately.
