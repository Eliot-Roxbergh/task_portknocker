# Port Knocking PoC

## Overview

A proof-of-concept application for portknocking.
Specifically, after the correct secret is given over UDP, a TLS server is started.
In addition, only clients who sent the correct secret prior may access the TLS server (source IP whitelisting)

The program consists of a small executable capable of starting a client or server, 'portknock'.
As well as a shared library which provides the back-end functionality, 'libpknock.so' (using POSIX sockets and OpenSSL TLS).

Currently, this is a single-threaded program so the server only does one thing at a time.
First it awaits a correct secret on UDP.
Then it _instead_ opens up TLS for that source IP who sent the secret


```
Steps:

1a) Server listens to UDP/53
1b) Client sends a hardcoded secret directly to server via UDP
2)  If secret is correct, server adds client to list of whitelisted IPs
    - else both client and server quits with error code.
3a) Server now opens a TLS/443 socket instead, and instead of matching on a secret
    the server now only allows the specific IP whitelisted in prior step
3b) The client connects, and if the source IP matches the whitelist,
    some messages are exchanged over this secure channel.
    - else both client and server quits with error code.
4)  Server and client terminates, OK

```

### Extra Features Implemented

TLS server only accepts whitelisted client IP addresses, otherwise the TCP connection is instantly terminated.

### Future Features

Mainly three things are missing:

First, multithreading, to enable the server to simultaneously accept new client secrets on UDP while
serving them on TLS. Now only one client can use a server.

Second, the configuration is currently hardcoded in 'include/config.h',
including the server IP, ports, and certificates. Thus rebuilding the application is needed to change the config.
It would not be too hard to add these parameter to the tool.

Third, the key is currently sent in plaintext.
It would be preferred if it somehow was sent as a unique signature/nonce/derived secret.
There are a number of ways to do this, the goal being to avoid replay attacks.


Additionally several smaller suggestion are listed in the code, search for [improvement].


## File Structure

__build/__ - run build and tests here. Also artifacts, including binaries, end up here.

__cert/__  - credentials for TLS communication

__src/__   - source code for the library (libpknock.so)

__tool/__  - source code for the binary  (portknock)

__test/__  - source code for the tests (unit tests with GoogleTest, and Valgrind on those tests)

__include/__ - public header files, including configuration (server port, IP, etc.)

__./CMakeLists.txt__ - build configuration

__./README__ - this file

__./CHANGELOG__ - version changelog


## Build and Test

Coded for OpenSSL 1.1.1 (req. >= 1.1.1).

Tested on Ubuntu 18.04.

Each commit has been tested with the test available at that time (unit tests / valgrind), as well as basic manual testing.

Note, since the default ports are <1024, root priviliges is usually needed to run this program.
Or the ports can be changed by modifying include/config.h, and then running "make".

### Building for Production

```
mkdir build; cd build;
cmake .. -DCMAKE_BUILD_TYPE=Release -DUNIT_TEST=false
make
```

#### Running the Project

The binary has both client and server capabilities.

```
cd build
./portknock help

# Start client or server (default secret hard-coded in library)
./portknock
./portknock server

# Or with custom secret
./portknock server My_secret_key01
./portknock My_secret_key01

```

### Building for Test

```
mkdir build; cd build;
cmake .. -DCMAKE_BUILD_TYPE=Debug -DUNIT_TEST=true
make
```

### Run Tests

The following tests are supported in the cmake file:
GoogleTest (unit tests), Valgrind (memcheck), lcov (code coverage), CodeChecker (static analysis)


```
make codechecker # Static analysis

make test        # Unit tests + memcheck
ctest -V         # Same as above, but verbose (this is useful)

make coverage    # Show code coverage for the unit tests
```

#### Quick Oneliner

```
# Rebuild and run all tests
cd build; rm CMakeCache.txt CMakeFiles Makefile -rf; cmake .. -DCMAKE_BUILD_TYPE=Debug -DUNIT_TEST=true && make && ctest -V
```

#### Prerequisites

```
sudo apt update
sudo apt install -y gcc valgrind clang clang-tidy openssl libssl-1.1 libssl-dev python3-pip lcov
pip3 install --user codechecker
```

clang-7, clang-tidy-7 or later is required.

Tested with GCC 8.4.0, clang / clang-tidy 10, CodeChecker 6.19.1, lcov 1.13 / gcov 8.3.0

Note that newer versions of gcc and clang-tidy will potentially find more warnings during compilation and static analysis (this is good).


#### Code Style

Code is automatically formated with clang-format, see _CMakeLists.txt_ for details

To format all source files in-place, run:

```
make clangformat
```
