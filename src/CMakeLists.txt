ADD_LIBRARY( 
   "grypt" STATIC
   encryption.cpp 
)

if(GCRYPT_IMPL STREQUAL "openssl")
   add_subdirectory(openssl)
endif()
