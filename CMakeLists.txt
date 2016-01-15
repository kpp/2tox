cmake_minimum_required(VERSION 2.8.4)

project(2tox C CXX)
enable_testing()

set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} ${CMAKE_SOURCE_DIR}/cmake)

find_package(Threads REQUIRED)
find_package(Sodium REQUIRED)

include(CMakeDependentOption)
include(FeatureSummary)
include(GTest)

option(BUILD_TESTING "Build the testing tree." ON)
ADD_FEATURE_INFO(BUILD_TESTING BUILD_TESTING "Build unit tests")

SET_PACKAGE_PROPERTIES(Sodium PROPERTIES TYPE REQUIRED
    URL "https://download.libsodium.org/doc/"
    DESCRIPTION "Software library for encryption, decryption, signatures, password hashing and more"
)

FEATURE_SUMMARY(WHAT ALL)

#

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ") # TODO
set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} ") # TODO
set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} ") # TODO
set(CMAKE_CXX_FLAGS_COVERAGE "--coverage")

include_directories(${CMAKE_SOURCE_DIR})
include_directories(${SODIUM_INCLUDE_DIR})
add_subdirectory(toxcore/)
add_subdirectory(toxdns/)
add_subdirectory(toxencryptsave/)
add_subdirectory(toxav/)
add_subdirectory(tests/)

# uninstall target

configure_file("${CMAKE_SOURCE_DIR}/cmake/uninstall.cmake.in" uninstall.cmake @ONLY)
add_custom_target(uninstall COMMAND ${CMAKE_COMMAND} -P uninstall.cmake)

# package info

set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "2tox, reimplementation of toxcore")
set(CPACK_DEBIAN_PACKAGE_DESCRIPTION # The format of Description: http://www.debian.org/doc/debian-policy/ch-controlfields.html#s-f-Description
"2tox
 Reimplementation of toxcore
")
set(CPACK_PACKAGE_CONTACT "Roman Proskuryakov <humbug@deeptown.org>")
set(CPACK_PACKAGE_VERSION_MAJOR "0")
set(CPACK_PACKAGE_VERSION_MINOR "0")
set(CPACK_PACKAGE_VERSION_PATCH "0")
set(CPACK_RESOURCE_FILE_LICENSE "${CMAKE_SOURCE_DIR}/LICENSE")
set(CPACK_SOURCE_GENERATOR "TGZ")
set(CPACK_SOURCE_IGNORE_FILES "build/" "\\\\.kdev.*" "\\\\.git.*" "\\\\.hgignore")
set(CPACK_STRIP_FILES "")

set(CPACK_GENERATOR "DEB")
set(CPACK_DEBIAN_PACKAGE_HOMEPAGE "https://github.com/kpp/2tox")
set(CPACK_DEBIAN_PACKAGE_DEPENDS "")

include(CPack)
