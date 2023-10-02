cmake_minimum_required(VERSION 3.6)
set(CMAKE_C_COMPILER /usr/bin/gcc)
project(PortKnock VERSION 0.1 LANGUAGES C)

find_package(OpenSSL REQUIRED)
find_package(PkgConfig REQUIRED)
pkg_check_modules(OPENSSL openssl>=1.1.1 REQUIRED)

###############################################
##               Build Options               ##
###############################################
set(C_STD gnu11)

#NOTE: Some of these compiler flags are most surely GCC specific,
#       and some security flags are hw specific such as fcf-protection (uses Intel CET, according to GCC-12)
if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    set(CMAKE_EXPORT_COMPILE_COMMANDS ON) #CodeChecker
    message("Debug build")
    set(CMAKE_VERBOSE_MAKEFILE 1)
    set(C_FLAGS_DEBUG    " -g -Og -fasynchronous-unwind-tables -fexceptions -fno-omit-frame-pointer ")
    set(C_FLAGS_WARNINGS " -Wall -Wextra -pedantic -Werror -Wformat=2 -Wconversion -Wdouble-promotion -Wshadow -Wundef ")

    # Additional warnings, in some cases these can be ignored (that's the idea at least)
    # TODO: CodeChecker might complain on -fanalyzer flag
    set(C_FLAGS_WARNINGS_EXTRA " -fanalyzer -Wcast-qual -Wcast-align -Wredundant-decls -Winline -Wdisabled-optimization -Wnested-externs \
                                 -fstrict-aliasing ") #more: -Wmissing-prototypes -Wmissing-declarations
    set(C_FLAGS_RUNTIME_CHECKS " -fsanitize=address,undefined ") #TODO testing this, warns during runtime
else()
    message("Release build")
    set(CMAKE_POSITION_INDEPENDENT_CODE ON) #(this should be default on)
    set(C_FLAGS_DEBUG    " -O3 ")
    set(C_FLAGS_SECURITY " -D_FORTIFY_SOURCE=2  -D_GLIBCXX_ASSERTIONS -fcf-protection=full -fstack-protector-strong \
                           -Wl,-z,noexecstack -Wl,-z,now -Wl,-z,relro -Wl,-z,defs ") #more: -fstack-clash-protection
endif()

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -std=${C_STD} ${C_FLAGS_DEBUG} ${C_FLAGS_WARNINGS} ${C_FLAGS_WARNINGS_EXTRA} ${C_FLAGS_SECURITY} ${C_FLAGS_RUNTIME_CHECKS} -fno-common")

# (TODO) Example for building against other openssl than system default
#           or use FindOpenSSL.cmake ?
#include_directories("${OPENSSL_INCLUDE_DIR}")
#link_directories("${OPENSSL_CRYPTO_LIBRARIES}" "${OPENSSL_SSL_LIBRARIES}")
#add_definitions("${OPENSSL_CFLAGS_OTHER}")

# The library - pknock
add_library(pknock SHARED src/client.c src/helper.c src/server.c)
target_link_libraries (pknock -lcrypto -lssl)
target_include_directories(pknock PRIVATE src/)
target_include_directories(pknock PUBLIC  include/)
set_target_properties(pknock PROPERTIES
                              VERSION ${PROJECT_VERSION}
                            SOVERSION ${PROJECT_VERSION_MAJOR})

# The binary tool - portknock
add_executable(portknock tool/portknock.c)
target_link_libraries (portknock pknock)
target_include_directories(portknock PRIVATE src/)
target_include_directories(portknock PUBLIC  include/)

#To install: cmake --build . --target install
install(TARGETS portknock
        RUNTIME DESTINATION bin/)
install(TARGETS pknock
        LIBRARY DESTINATION lib/)
install(FILES include/config.h include/portknock.h
        DESTINATION include/)

###############################################
##                 Unit Tests                ##
##                    AND                    ##
##                 Mem check                 ##
###############################################
# GoogleTest + Valgrind
if (UNIT_TEST)
    include(CTest)
    add_subdirectory(test/)

# Run CodeCoverage on unit tests
# make coverage
# Prerequisites: sudo apt install -y lcov
    set(CMAKE_COMPILER_IS_GNUCXX true) #ugly hack, it bugged for me (TODO, perhaps because C project, not CXX?)
    include(test/CodeCoverage.cmake)
    APPEND_COVERAGE_COMPILER_FLAGS()
    setup_target_for_coverage_lcov(
        NAME coverage
        EXECUTABLE ${CMAKE_BINARY_DIR}/test/unit_tests
        EXCLUDE "/usr/include/*" "gtest/*"
        DEPENDENCIES portknock pknock
    )
endif()

###############################################
##              Static Analysis              ##
###############################################
add_custom_target(
    codechecker_analyze
    COMMAND CodeChecker analyze "compile_commands.json" -o reports;
    # Note: 'extreme' is noisy, tweak accordingly (e.g. disable warnings below)
    --enable extreme;
    --clean;
    --ignore "../.SKIPFILE" ;

    #Feel free to disable --ctu and --stats if not in your CodeChecker version
    --ctu;
    #--stats;

    #Disable certain style warnings
    -d google-readability-braces-around-statements; #buggy
    -d google-readability-todo;
    -d cppcoreguidelines-avoid-magic-numbers;
    -d cppcoreguidelines-init-variables;

    # Optional, can disable these warnings
    -d misc-no-recursion;
    # (Check only some unused return value functions)
    -d cert-err33-c
    -e bugprone-unused-return-value
    #
)
add_custom_target(
    codechecker
    DEPENDS codechecker_analyze
    COMMAND CodeChecker parse ./reports;
)

###############################################
##                   Linter                  ##
###############################################
add_custom_target(
    clangformat_create
    COMMAND clang-format;
    -style='{
             BasedOnStyle: Google, IndentWidth: 4, BreakBeforeBraces: Linux, ColumnLimit: 120,
             AlignEscapedNewlines: Left, AlignOperands: true, AlignTrailingComments: true
            }' ;
    --dump-config > .clang-format
)
add_custom_target(
    clangformat
    DEPENDS clangformat_create
    COMMAND clang-format ../src/*.[ch] ../include/*.[ch] ../tool/*.[ch] ../test/*.cc -i
)

