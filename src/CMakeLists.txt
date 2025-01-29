add_library( 
   "grypt" INTERFACE
)

add_subdirectory(util)

if(GCRYPT_IMPL STREQUAL "openssl")
   add_subdirectory(openssl)
endif()
