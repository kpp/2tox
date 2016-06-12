add_library(toxencryptsave
    constants.cpp
    key.cpp
    mem_guard.cpp
    reader.cpp
    writer.cpp
    toxencryptsave.cpp
)
target_link_libraries(toxencryptsave toxcore ${SODIUM_LIBRARIES})
