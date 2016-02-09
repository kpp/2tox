add_library(toxencryptsave toxencryptsave.cpp)
target_link_libraries(toxencryptsave toxcore ${SODIUM_LIBRARIES})
