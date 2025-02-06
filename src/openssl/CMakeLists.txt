ADD_LIBRARY( 
   "gryptssl" STATIC
   osslutil.cpp
   algorithm_ossl.cpp
   randombytes_ossl.cpp
   symmetrickeycipher_ossl.cpp
)

target_link_libraries(gryptssl ssl crypto gryptutil)
target_link_libraries(grypt INTERFACE gryptssl)