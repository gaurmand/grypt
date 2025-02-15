add_executable(
   encryption_test
   algorithm_test.cpp
   symmetriccipher_test.cpp
   authsymmetriccipher_test.cpp
   asymmetriccipher_test.cpp
   hash_test.cpp
   mac_test.cpp
)

add_executable(
   util_test
   bytes_test.cpp
)

target_link_libraries(
   encryption_test
   "grypt"
   gtest
   gtest_main
)

target_link_libraries(
   util_test
   "grypt"
   gtest
   gtest_main
)

target_include_directories(encryption_test PRIVATE "../src/")
target_include_directories(util_test PRIVATE "../src/")

gtest_discover_tests(
   encryption_test
   WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
)

gtest_discover_tests(
   util_test
   WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
)
