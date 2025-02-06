cmake_minimum_required(VERSION 3.14)
project(grypt)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_FLAGS "-Wall -Werror")

include_directories("include")

set(GCRYPT_IMPL "openssl") # use openssl backend

enable_testing()
include(GoogleTest)
add_subdirectory(src)
add_subdirectory(tests)
