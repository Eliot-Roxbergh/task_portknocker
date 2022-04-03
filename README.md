# Port Knocking PoC

## Overview

One executable capable of starting client and server, 'portknock'.

This functionality is provided by the dynamic library, 'libpknock.so' (using POSIX sockets and OpenSSL TLS).


```
[server listens to port 53/udp, port 443/tcp is closed]
1a. client sends hardcoded message (key)
1b. message is received by server, which starts TLS listener on 443
[port knocking sequence completed]
2. client initiates TLS connection on port 443 to server
[regular TLS traffic is allowed]
```


### Tests

Each commit has been tested with the test available at that time (unit tests / valgrind), as well as basic manual testing.


### Optional Features

Ideas that could be implemented;

__(TODO!)__

```
i) client encrypts something with the shared key. This ciphertext is sent instead of the key.
    e.g.
    Such as encrypt current time or day, to limit replay attacks (assumes working clocks and the same time zone).
    Or its public IP address for the same reasons (a bit hard if server is on local network etc).

ii) TLS listener should only accept whitelisted IPs

iii)  Ideally, server can have both 53 and 443 opened. This requires ii) to be useful, and the use of multiple threads
        would be best.
```


See also tag _[IMPROVEMENT suggestion]_ in code for more ideas.




## File Structure

__build/__ - build here -> artifacts, including binaries

__src/__   - source code for the library (libpknock.so)

__tool/__  - source code for the binary  (portknock)

__test/__  - source code for the tests (unit tests with GoogleTest +Valgrind on those tests)

__include/__ - public header files

__./CMakeLists.txt__ - build configuration

__./README__ - this file

__./CHANGELOG__ - version changelog


## Build and Test

Coded for OpenSSL 1.1.1

### Building for Production

```
mkdir build; cd build;
cmake .. -DCMAKE_BUILD_TYPE=Release -DUNIT_TEST=false
make
```

#### Running the Project

The binary has both client and server capabilities, all you need.

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

```
make codechecker # Static analysis

make test        # Unit tests + memcheck
```

#### Quick Oneliner

```
# Rebuild and run all tests
mkdir build
cd build; rm CMakeCache.txt CMakeFiles Makefile -rf; cmake .. -DCMAKE_BUILD_TYPE=Debug -DUNIT_TEST=true && make && make test && make codechecker
```

#### Prerequisites

```
sudo apt update
sudo apt install -y gcc valgrind clang clang-tidy openssl libssl-1.1 libssl-dev python3-pip
pip3 install --user codechecker
```

clang-7, clang-tidy-7 or later is required.

Tested with GCC 8.4.0, clang / clang-tidy 10, CodeChecker 6.19.1

Note that newer versions of gcc and clang-tidy will potentially find more warnings during compilation and static analysis (this is good).


#### Code Style

Code is automatically formated with clang-format, see _CMakeLists.txt_ for details

To format all source files in-place, run:

```
make clangformat
```
