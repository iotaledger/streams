ifeq ($(shell uname),Darwin)
    LDFLAGS := -Wl
	LD_LIBRARY_PATH := ./target/debug/libiota_streams_c.dylib
else
    LDFLAGS := -Wl,--gc-sections -lpthread -ldl
	LD_LIBRARY_PATH := ./target/debug/libiota_streams_c.so
endif


target/streams: target/main.o $(LD_LIBRARY_PATH)
	$(CC) -o $@ $^ $(LDFLAGS)

target:
	mkdir -p $@

$(LD_LIBRARY_PATH): src/lib.rs Cargo.toml
	cargo build --target-dir ./target
	ls ./target/debug

target/main.o: main.c include/streams.h | target
	$(CC) -o $@ -c $<

clean:
	rm -rf target