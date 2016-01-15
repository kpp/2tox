file(GLOB CORE_SRC "*.cpp")
add_library(toxcore ${CORE_SRC})
target_link_libraries(toxcore ${SODIUM_LIBRARIES})
