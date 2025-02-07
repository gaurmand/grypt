ADD_LIBRARY( 
   "gryptssl" STATIC
   osslutil.cpp
   algorithm_ossl.cpp
   randombytes_ossl.cpp
   symmetriccipher_ossl.cpp
   authsymmetriccipher_ossl.cpp
)

target_link_libraries(gryptssl ssl crypto gryptutil)
target_link_libraries(grypt INTERFACE gryptssl)