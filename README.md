# Cifra
Cifra is a collection of cryptographic primitives targeted at embedded use.

[![Build Status](https://travis-ci.org/ctz/cifra.svg?branch=master)](https://travis-ci.org/ctz/cifra)

[![Documentation](https://readthedocs.org/projects/pip/badge/)](https://cifra.readthedocs.org/en/latest/)

[![Analysis Status](https://scan.coverity.com/projects/4324/badge.svg)](https://scan.coverity.com/projects/4324)

[![Coverage Status](https://coveralls.io/repos/ctz/cifra/badge.svg?branch=coveralls-scan)](https://coveralls.io/r/ctz/cifra?branch=coveralls-scan)

## Aims
In order of descending emphasis, cifra aims for:

* **Clarity** and **simplicity**.
* Countermeasures for side channel leaks inherent in some
  algorithms.
* Suitability for embedded use.  Particularly: cifra uses an
  absolute minimum of the standard C library and is reasonably
  efficient with respect to code and data space.

## Features
* **AES** in the **GCM**, **CCM** and **EAX** authenticated encryption modes.
* **SHA224**, **SHA256**, **SHA384** and **SHA512** hash functions (including **HMAC** and **PBKDF2**).
* **SHA3-224**, **SHA3-256**, **SHA3-384**, **SHA3-512** hash functions (FIPS 202 draft compatible).
* **ChaCha20** and **Salsa20** stream ciphers.
* 100% code coverage by line, zero static analysis defects, valgrind-clean.

Additionally cifra imports curve25519 from elsewhere (nacl, tweetnacl,
Adam Langley's donna) for comparison between various implementations
on embedded targets.

## Documentation
Available at [Read the Docs](https://cifra.readthedocs.org/en/latest/).

## Testing
There is quite a lot of testing available:

* **Host builds**: run `make test` in the `src` directory.  This builds and
  runs assorted test programs.
* **Emulated embedded builds**: run `make test` in the `src/arm` directory.  This
  expects to find `qemu-system-gnuarmeclipse` on the path.  These tests assume
  a Cortex-M0 target.
* **Cortex-M0 on-target tests**: run `make test.stm32f0` in the `src/arm` directory.
  This expects to find `openocd` on the path, with an STM32F0xx attached via
  stlinkv2.  It uses ARM semihosting to report results.
* **Cortex-M3/4 on-target tests**: run `make test.stm32f1` or `make test.stm32f3` as above.

Additionally all embedded targets expect to find the `arm-none-eabi` toolchain
to be on the path.

## Measurements
All measurements performed at `-Os` (optimise for space), on the following MCUs: 

Core       | Part number   | Price (1s)   | Max clock  | Flash | SRAM
---------- | ------------- | ------------ | ---------- | ----- | -----
Cortex-M0  | STM32F030F4P6 | 1.17EUR      | 48MHz      | 16KB  | 4KB
Cortex-M3  | STM32F103C8T6 | 2.87EUR      | 72MHz      | 64KB  | 20KB
Cortex-M4F | STM32F303K6T6 | 4.53EUR      | 72MHz      | 32KB  | 12KB

## AES
This test does a key schedule, then encrypts one block.

### 128-bit key
Core       | Cycles (key schedule + block) | Cycles (key schedule) | Cycles (block) | Stack | Code size
---------- | ----------------------------- | --------------------- | -------------- | ----- | ---------
Cortex-M0  | 7083                          | 2113                  | 4970           | 312B  | 1068B    
Cortex-M3  | 4682                          | 1595                  | 3087           | 300B  | 1008B    
Cortex-M4F | 4559                          | 1553                  | 3006           | 300B  | 1008B    

### 256-bit key
Core       | Cycles (key schedule + block) | Cycles (key schedule) | Cycles (block) | Stack | Code size
---------- | ----------------------------- | --------------------- | -------------- | ----- | ---------
Cortex-M0  | 10480                         | 3558                  | 6922           | 396B  | 1140B    
Cortex-M3  | 6684                          | 2414                  | 4270           | 380B  | 1100B    
Cortex-M4F | 6539                          | 2381                  | 4158           | 380B  | 1100B    


## AES128-GCM
This test encrypts and authenticates a 16 byte message,
with 16 bytes additionally authenticated data.  It includes
the initial key schedule.

Core       | Cycles | Stack | Code size
---------- | ------ | ----- | ---------
Cortex-M0  | 56808  | 828B  | 2660B    
Cortex-M3  | 43092  | 836B  | 2716B    
Cortex-M4F | 43179  | 836B  | 2716B    

## AES128-EAX
This test encrypts and authenticates a 16 byte message,
with 16 bytes additionally authenticated data.  It includes
the initial key schedule.

Core       | Cycles | Stack | Code size
---------- | ------ | ----- | ---------
Cortex-M0  | 49829  | 928B  | 2620B    
Cortex-M3  | 32630  | 924B  | 2592B    
Cortex-M4F | 31922  | 924B  | 2592B    

## AES128-CCM
This test encrypts and authenticates a 16 byte message,
with 16 bytes additionally authenticated data.  It includes
the initial key schedule.

Core       | Cycles | Stack | Code size
---------- | ------ | ----- | ---------
Cortex-M0  | 40096  | 808B  | 2332B    
Cortex-M3  | 26594  | 796B  | 2280B    
Cortex-M4F | 26018  | 796B  | 2280B    

## Chacha20
This test encrypts a 64 byte message.

Core       | Cycles | Stack | Code size
---------- | ------ | ----- | ---------
Cortex-M0  | 5631   | 568B  | 1328B    
Cortex-M3  | 3449   | 568B  | 1360B    
Cortex-M4F | 3342   | 568B  | 1360B    

(For comparison with AES, add an AES256 key schedule plus 4 blocks.
That's about 33K cycles.)

## Salsa20
This test encrypts a 64 byte message.

Core       | Cycles | Stack | Code size
---------- | ------ | ----- | ---------
Cortex-M0  | 5780   | 568B  | 1336B    
Cortex-M3  | 3222   | 572B  | 1272B    
Cortex-M4F | 3137   | 572B  | 1272B    

## SHA256
This test hashes the empty string (one compression function invocation).

Core       | Cycles | Stack | Code size
---------- | ------ | ----- | ---------
Cortex-M0  | 21804  | 460B  | 1476B    
Cortex-M3  | 15591  | 456B  | 1508B    
Cortex-M4F | 15432  | 456B  | 1508B    

## SHA512
This test hashes the empty string (one compression function invocation).

Core       | Cycles | Stack | Code size
---------- | ------ | ----- | ---------
Cortex-M0  | 55709  | 780B  | 2544B    
Cortex-M3  | 43258  | 836B  | 2676B    
Cortex-M4F | 42884  | 836B  | 2676B    

## SHA3-256
This test hashes the empty string (one sponge permutation).

Core       | Cycles | Stack | Code size
---------- | ------ | ----- | ---------
Cortex-M0  | 86857  | 1024B | 1960B    
Cortex-M3  | 77621  | 1008B | 1944B    
Cortex-M4F | 73663  | 1008B | 1944B    

## SHA3-512
This test hashes the empty string (one sponge permutation).

Core       | Cycles | Stack | Code size
---------- | ------ | ----- | ---------
Cortex-M0  | 86210  | 1056B | 1960B    
Cortex-M3  | 77206  | 1040B | 1944B    
Cortex-M4F | 73256  | 1040B | 1944B    

## Curve25519 (tweetnacl)
This test is one point multiplication.

Core       | Cycles   | Stack | Code size
---------- | -------- | ----- | ---------
Cortex-M0  | 88696559 | 1720B | 1600B    
Cortex-M3  | 30659678 | 1684B | 1556B    
Cortex-M4F | 27143515 | 1684B | 1556B    

See [curve25519-shootout](curve25519-shootout.md) for comparison
between the included curve25519 implementations.

## C library requirements
Cifra requires `memcpy`, `memset`, `abort` and `assert`.

## Future
* ~~Keccak hash function (aka SHA3)~~.
* Poly1305 one-time MAC.
* Constant time curve25519 for Cortex-M4F using the FPU.
* Constant time curve25519 for Cortex-M3 (avoiding the variable-time multiplier).

## License
[CC0](https://creativecommons.org/publicdomain/zero/1.0/).

Please attribute the author.  This is a request only, and not a license term.

## Author
Joseph Birr-Pixton <jpixton@gmail.com>
