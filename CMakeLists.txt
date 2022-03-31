cmake_minimum_required(VERSION 3.6)
project(PortKnock VERSION 0.0 LANGUAGES C)

###############################################
##               Build Options               ##
###############################################
set(C_STD gnu11)
IF(CMAKE_BUILD_TYPE STREQUAL "Debug")
    message("Debug build")
    set(CMAKE_VERBOSE_MAKEFILE 1)
    set(C_FLAGS_DEBUG    " -g -Og -fasynchronous-unwind-tables -fexceptions ")
    set(C_FLAGS_WARNINGS " -Wall -Wextra -pedantic -Werror -Wformat=2 -Wconversion -Wdouble-promotion -Wshadow -Wundef ")
ELSE()
    message("Release build")
    set(CMAKE_POSITION_INDEPENDENT_CODE ON)
    set(C_FLAGS_DEBUG    " -O3 ")
    set(C_FLAGS_SECURITY " -D_FORTIFY_SOURCE=2  -D_GLIBCXX_ASSERTIONS -fcf-protection=full -fstack-protector-strong \
                           -Wl,-z,noexecstack -Wl,-z,now -Wl,-z,relro -Wl,-z,defs ") #-fstack-clash-protection
ENDIF()

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -std=${C_STD} ${C_FLAGS_DEBUG} ${C_FLAGS_WARNINGS} ${C_FLAGS_SECURITY} -fno-common")
set(CMAKE_C_COMPILER /usr/bin/gcc)

add_executable(client src/client.c)
add_executable(server src/server.c)

###############################################
##                 Unit Tests                ##
##                    AND                    ##
##                 Mem check                 ##
###############################################
# GoogleTest + Valgrind
if (UNIT_TEST)
    include(CTest)
    add_subdirectory(test/)
endif()

###############################################
##              Static Analysis              ##
###############################################
add_custom_target(
    codechecker_build
    make clean
    COMMAND CodeChecker log --build "make" ;
    --output "./compile_commands.json" ;
)
add_custom_target(
    codechecker_analyze
    DEPENDS codechecker_build
    COMMAND CodeChecker analyze "compile_commands.json" -o reports;
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
    COMMAND clang-format ../src/*.[ch] ../include/*.[ch] -i
)
