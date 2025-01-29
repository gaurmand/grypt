ADD_LIBRARY( 
   "gryptutil" STATIC
   bytes.cpp
   error.cpp
)

target_link_libraries(grypt INTERFACE gryptutil)