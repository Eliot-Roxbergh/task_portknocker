cmake_minimum_required(VERSION 3.0.0)
project(portknock-tests VERSION 1)
set(CMAKE_CXX_STANDARD 11)
set(CMAKE_VERBOSE_MAKEFILE 1)

# Initially taken from:
#    https://google.github.io/googletest/quickstart-cmake.html
#    https://github.com/google/googletest/commit/5065389aabfa1d70a49d57eb355b9db4500801be

# Using older method to support cmake verisons < 3.14
#   see https://github.com/google/googletest/commit/5065389aabfa1d70a49d57eb355b9db4500801be
# Download and unpack googletest at configure time
configure_file(CMakeLists.txt.in googletest-download/CMakeLists.txt)
execute_process(COMMAND ${CMAKE_COMMAND} -G "${CMAKE_GENERATOR}" .
    RESULT_VARIABLE result
    WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/googletest-download )
if(result)
    message(FATAL_ERROR "CMake step for googletest failed: ${result}")
endif()
execute_process(COMMAND ${CMAKE_COMMAND} --build .
    RESULT_VARIABLE result
    WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/googletest-download )
if(result)
    message(FATAL_ERROR "Build step for googletest failed: ${result}")
endif()

# Prevent overriding the parent project's compiler/linker settings on Windows
#set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)

include(GoogleTest)
# Add googletest directly to our build. This defines the gtest and gtest_main targets.
add_subdirectory(${CMAKE_CURRENT_BINARY_DIR}/googletest-src
                 ${CMAKE_CURRENT_BINARY_DIR}/googletest-build
                 EXCLUDE_FROM_ALL)

add_executable(unit_tests unit_tests.cc)
target_link_libraries(unit_tests gtest_main pknock)
target_include_directories(unit_tests PRIVATE ../src)
target_include_directories(unit_tests PUBLIC  ../include)

# Check all unit tests for memory issues
add_test(memcheck_unit_tests valgrind
         --error-exitcode=1
         --leak-check=full
         --show-leak-kinds=all
         ${CMAKE_BINARY_DIR}/test/unit_tests)

gtest_discover_tests(unit_tests)
