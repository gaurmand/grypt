ADD_LIBRARY( 
   "gryptssl" STATIC
   osslutil.cpp
   pkey_util.cpp
   algorithm_ossl.cpp
   randombytes_ossl.cpp
   symmetriccipher_ossl.cpp
   authsymmetriccipher_ossl.cpp
   asymmetriccipher_ossl.cpp
   hash_ossl.cpp
   mac_ossl.cpp
   digitalsignature_ossl.cpp
)

target_link_libraries(gryptssl ssl crypto gryptutil)
target_link_libraries(grypt INTERFACE gryptssl)