cmake_minimum_required(VERSION 3.3.0)
project(iota_streams_c)

option(NO_STD "Enable no_std build, without iota_client" OFF)
option(SYNC_CLIENT "Enable sync transport via iota_client" ON)
option(STATIC "Build shared library" OFF)

set(cargo_features "")
if(${NO_STD})
else(${NO_STD})
  set(cargo_features "std,")
endif(${NO_STD})

if(${SYNC_CLIENT})
  add_definitions(-DIOTA_STREAMS_CHANNELS_CLIENT)
  set(cargo_features "${cargo_features}sync-client")
endif(${SYNC_CLIENT})
include_directories(include/)

add_executable(iota_streams_c main.c)

if(${STATIC})
  message("STATIC")
  add_custom_command(TARGET iota_streams_c PRE_BUILD COMMAND cargo build --target-dir ../../../target --no-default-features --features "${cargo_features}")
  target_link_libraries(iota_streams_c ../../../target/debug/iota_streams_c)

else(${STATIC})
  message("SHARED")
  add_custom_command(TARGET iota_streams_c PRE_BUILD COMMAND cargo build --target-dir ../../../target --no-default-features --features "${cargo_features}" COMMAND copy /Y ..\\..\\..\\target\\debug\\iota_streams_c.dll .)
  target_link_libraries(iota_streams_c ../../../target/debug/iota_streams_c.dll)

endif()
