
add_custom_target(check COMMAND ${CMAKE_CTEST_COMMAND} --output-on-failure --parallel 4)

if (NOT BUILD_TESTING)
    return()
endif()

# cxx_test(
#   PRETTY_NAME name
#   BIN_NAME binary_name
#   SOURCES list_of_sources
#   [LIBS list_of_link_libraries]
#   [WITH_MAIN_F]
# )
# WITH_MAIN_F - do not use GTest default main function(which runs tests), but produce custom function instead
include(CMakeParseArguments)
function(cxx_test) # function to register tests. see examples below
    set(options WITH_MAIN_F)
    set(one_value_args PRETTY_NAME BIN_NAME)
    set(multi_value_args SOURCES LIBS)
    CMAKE_PARSE_ARGUMENTS(TEST "${options}" "${one_value_args}" "${multi_value_args}" ${ARGN})

    if (NOT TEST_PRETTY_NAME OR NOT TEST_BIN_NAME OR NOT TEST_SOURCES)
        message(FATAL_ERROR "Arguments PRETTY_NAME, BIN_NAME, SOURCES are required!")
    endif()
    if (TEST_UNPARSED_ARGUMENTS)
        message(FATAL_ERROR "Arguments were not parsed during creation of tests: ${TEST_UNPARSED_ARGUMENTS}")
    endif()

    add_executable(${TEST_BIN_NAME} ${TEST_SOURCES})
    target_link_libraries(${TEST_BIN_NAME} ${TEST_LIBS})
    if(TEST_WITH_MAIN_F)
        target_link_libraries(${TEST_BIN_NAME} ${GTEST_LIBRARIES} ${CMAKE_THREAD_LIBS_INIT})
    else()
        target_link_libraries(${TEST_BIN_NAME} ${GTEST_BOTH_LIBRARIES} ${CMAKE_THREAD_LIBS_INIT})
    endif()

    #GTEST_ADD_TESTS(${TEST_BIN_NAME} "" ${TEST_SOURCES})
    add_test(NAME ${TEST_PRETTY_NAME} COMMAND ${TEST_BIN_NAME})
    add_dependencies(check ${TEST_BIN_NAME})
endfunction()

include_directories(${GTEST_INCLUDE_DIR})
include(RegisterTests.cmake)
