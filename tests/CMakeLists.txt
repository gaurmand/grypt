add_executable(
   encryption_test
   encryption_test.cpp
)

target_link_libraries(
   encryption_test
   "grypt"
   gtest
   gtest_main
)

gtest_discover_tests(encryption_test)
