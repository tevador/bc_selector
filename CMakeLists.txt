cmake_minimum_required(VERSION 3.5)

if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release)
  message(STATUS "Setting default build type: ${CMAKE_BUILD_TYPE}")
endif()

project(bc_selector)

add_executable(${PROJECT_NAME}
src/bcselect.c
src/bcselect_lmdb.c
src/chacha_rng.c
src/keccak.c
src/main.c
src/mdb.c
src/midl.c
src/timing.c)

if(NOT Threads_FOUND AND UNIX AND NOT APPLE)
  find_package(Threads)
endif()

set_property(TARGET ${PROJECT_NAME} PROPERTY C_STANDARD 11)

target_link_libraries(${PROJECT_NAME}
    PRIVATE ${CMAKE_THREAD_LIBS_INIT})
