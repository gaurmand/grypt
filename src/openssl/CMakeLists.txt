ADD_LIBRARY( 
   "gryptssl" STATIC
   symmetric_encryption_ssl.cpp 
)

target_link_libraries(gryptssl ssl crypto)
target_link_libraries(grypt gryptssl)