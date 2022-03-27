# Port Knocking PoC

## Overview

Two executables, client and server (using POSIX sockets and OpenSSL TLS)

```
[server listens to port 53/udp, port 443/tcp is closed]
1a. client sends hardcoded message (key)
1b. message is received by server, which starts TLS listener on 443
[port knocking sequence completed]
2. client initiates TLS connection on port 443 to server
[regular TLS traffic is allowed]
```


### Basic Test Cases

1. server port 443 closed

2. server port 443 open when sending correct secret
   otherwise, server port 443 closed (due to no secret, or wrong secret)

### Optional Features

In addition to the requirements, these extra features are added:

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



## File Structure

__src/__   - source code files

__build/__ - build artifacts, including binaries

__./CMakeLists.txt__ - build configuration

__./README__ - this file


## Build and Test

Coded for OpenSSL 1.1.1

### Building for Production

```
mkdir build; cd build;
cmake .. -DCMAKE_BUILD_TYPE=Release
make
```

#### Running the Project

```
cd build
./server &
./client &
```

### Building for test

```
mkdir build; cd build;
cmake .. -DCMAKE_BUILD_TYPE=Debug
make
```

### Running Test Suite

```
ctest -T         # Dynamic analysis (memcheck)
make codechecker # Static analysis
```

Oneliner

```
cd build; rm CMakeCache.txt CMakeFiles Makefile -rf; cmake .. -DCMAKE_BUILD_TYPE=Debug && make && ctest -T && make codechecker
```

#### Prerequisites

```
sudo apt update
sudo apt install -y gcc valgrind clang clang-tidy openssl libssl-1.1 libssl-dev python3-pip
pip3 install --user codechecker
```

clang-7, clang-tidy-7 or later is required.

Tested with GCC 8.4.0, clang / clang-tidy 10, CodeChecker 6.19.1

Note that newer versions of gcc and clang-tidy will potentially find more warnings during compilation and static analysis.


#### Code Style

Code is automatically formated with clang-format, see _CMakeLists.txt_ for details

To format all source files in-place, run:

```
make clangformat
```