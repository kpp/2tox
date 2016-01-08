# We try to find GTest package,
#  if it was not found or we could not build simple test
#  then add gtest as external project

include(CheckCXXSourceCompiles)
include(CMakePushCheckState)
include(ExternalProject)
include(FindPackageMessage)

function(add_gtest_as_external)
    set(gtest_local_dir "/usr/src/gtest/")
    if (EXISTS "${gtest_local_dir}/CMakeLists.txt")
        set (gtest_url SOURCE_DIR ${gtest_local_dir})
        FIND_PACKAGE_MESSAGE(GTest "Trying to build GTest from local ${gtest_local_dir}" "[${gtest_local_dir}]")
    else()
        set(gtest_web_url "https://googletest.googlecode.com/files/gtest-1.7.0.zip")
        FIND_PACKAGE_MESSAGE(GTest "Trying to build GTest from ${gtest_web_url}" "[${gtest_web_url}]")
        set(gtest_url
            URL ${gtest_web_url}
            LOG_DOWNLOAD 1
        )
    endif()

    ExternalProject_Add(
        gtest-external
        ${gtest_url}
        LOG_CONFIGURE 0
        PREFIX ${CMAKE_CURRENT_BINARY_DIR}/gtest
        INSTALL_COMMAND ""
        CMAKE_ARGS
            -DCMAKE_BUILD_TYPE=${CMAKE_BUILD_TYPE}
            # We don't want to check compiler by subproject again
            -DCMAKE_CXX_COMPILER=${CMAKE_CXX_COMPILER}
            -DCMAKE_CXX_COMPILER_ID_RUN=TRUE
            -DCMAKE_CXX_COMPILER_WORKS=TRUE
            -DCMAKE_CXX_COMPILER_FORCED=TRUE
            -DCMAKE_C_COMPILER=${CMAKE_C_COMPILER}
            -DCMAKE_C_COMPILER_ID_RUN=TRUE
            -DCMAKE_C_COMPILER_WORKS=TRUE
            -DCMAKE_C_COMPILER_FORCED=TRUE
            # Import Threads variables
            -DCMAKE_THREAD_LIBS_INIT=${CMAKE_THREAD_LIBS_INIT}
            -DCMAKE_USE_PTHREADS_INIT=${CMAKE_USE_PTHREADS_INIT}
            -Dgtest_disable_pthreads=TRUE
            # Do not remove the next line. GTest contains code with some compiler warnings
            -DCMAKE_CXX_FLAGS=\ 
    )
    ExternalProject_Get_Property(gtest-external source_dir binary_dir)

    #set_target_properties(gtest-external PROPERTIES EXCLUDE_FROM_ALL TRUE)

    # include dir
    set(GTEST_INCLUDE_DIR "${source_dir}/include" CACHE PATH "Path to directory.")# FORCE)

    # lib gtest
    add_library(gtest IMPORTED STATIC GLOBAL)
    add_dependencies(gtest gtest-external)
    set(GTEST_LIBRARY gtest CACHE STRING "Imported library.")# FORCE)
    set(GTEST_LIBRARY_DEBUG gtest CACHE STRING "Imported library.")# FORCE)
    set_property(TARGET gtest PROPERTY
        IMPORTED_LOCATION "${binary_dir}/${CMAKE_STATIC_LIBRARY_PREFIX}gtest${CMAKE_STATIC_LIBRARY_SUFFIX}")

    # lib gtest_main
    add_library(gtest_main IMPORTED STATIC GLOBAL)
    add_dependencies(gtest_main gtest-external)
    set(GTEST_MAIN_LIBRARY gtest_main CACHE STRING "Imported library.")# FORCE)
    set(GTEST_MAIN_LIBRARY_DEBUG gtest_main CACHE STRING "Imported library.")# FORCE)
    set_property(TARGET gtest_main PROPERTY
        IMPORTED_LOCATION "${binary_dir}/${CMAKE_STATIC_LIBRARY_PREFIX}gtest_main${CMAKE_STATIC_LIBRARY_SUFFIX}")

    set(GTEST_BOTH_LIBRARIES "${GTEST_MAIN_LIBRARY}" "${GTEST_LIBRARY}" PARENT_SCOPE)
    set(GTEST_FOUND TRUE CACHE BOOL "GTEST_FOUND")# FORCE)
    set(GTEST_EXTERNAL TRUE CACHE BOOL "GTEST_EXTERNAL")
endfunction()

function(try_compile_gtest out_var)
    CMAKE_PUSH_CHECK_STATE()
    set(CMAKE_REQUIRED_LIBRARIES ${GTEST_BOTH_LIBRARIES} ${CMAKE_THREAD_LIBS_INIT})
    set(CMAKE_REQUIRED_INCLUDES ${GTEST_INCLUDE_DIR})
    CHECK_CXX_SOURCE_COMPILES("#include <gtest/gtest.h>\n TEST(dummy, test){}" ${out_var})
    CMAKE_POP_CHECK_STATE()
endfunction()

# By default GTEST_EXTERNAL=FALSE
if (NOT GTEST_EXTERNAL)
    find_package(GTest) # try to find internal package
    if (GTEST_FOUND)
        try_compile_gtest(GTEST_COMPILED_AND_LINKED)
    endif()
    if (NOT GTEST_FOUND OR NOT GTEST_COMPILED_AND_LINKED)
        # switch to external gtest forever
        unset(GTEST_LIBRARY CACHE)
        unset(GTEST_LIBRARY_DEBUG CACHE)
        unset(GTEST_MAIN_LIBRARY CACHE)
        unset(GTEST_MAIN_LIBRARY_DEBUG CACHE)
        unset(GTEST_INCLUDE_DIR CACHE)
        unset(GTEST_BOTH_LIBRARIES CACHE)
        unset(GTEST_FOUND CACHE)
        add_gtest_as_external()
    endif()
else()
    add_gtest_as_external()
endif()
