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

add_executable(${PROJECT_NAME} main.c)

if(${STATIC})
  message("STATIC")
  add_custom_command(TARGET ${PROJECT_NAME} PRE_BUILD COMMAND cargo build --target-dir ../../../target --no-default-features --features "${cargo_features}")
  target_link_libraries(${PROJECT_NAME} ../../../target/debug/iota_streams_c)

else(${STATIC})
  message("SHARED")
  if (WIN32)
    add_custom_command(TARGET ${PROJECT_NAME} PRE_BUILD COMMAND cargo build --target-dir ../../../target --no-default-features --features "${cargo_features}" COMMAND copy /Y ..\\..\\..\\target\\debug\\iota_streams_c.dll .)
    target_link_libraries(${PROJECT_NAME} ../../../target/debug/iota_streams_c.dll)
  elseif (UNIX)
    set(FAKE_TARGET fakeTarget)
    add_custom_target(fakeTarget cargo build --target-dir ../../target --no-default-features --features "${cargo_features}" COMMAND cp ../../target/debug/libiota_streams_c.so ${CMAKE_CURRENT_SOURCE_DIR})
    add_dependencies(${PROJECT_NAME} ${FAKE_TARGET})

    target_link_libraries(${PROJECT_NAME} ${CMAKE_CURRENT_SOURCE_DIR}/libiota_streams_c.so)
  endif (WIN32)
  

endif()
