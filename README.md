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
Cortex-M0  | 6958                          | 2064                  | 4894           | 312B  | 944B     
Cortex-M3  | 4582                          | 1541                  | 3041           | 300B  | 884B     
Cortex-M4F | 4481                          | 1520                  | 2961           | 300B  | 884B     

### 256-bit key
Core       | Cycles (key schedule + block) | Cycles (key schedule) | Cycles (block) | Stack | Code size
---------- | ----------------------------- | --------------------- | -------------- | ----- | ---------
Cortex-M0  | 10314                         | 3468                  | 6846           | 396B  | 1016B    
Cortex-M3  | 6576                          | 2351                  | 4225           | 380B  | 964B     
Cortex-M4F | 6431                          | 2318                  | 4113           | 380B  | 964B     

## AES128-GCM
This test encrypts and authenticates a 16 byte message,
with 16 bytes additionally authenticated data.  It includes
the initial key schedule.

Core       | Cycles | Stack | Code size
---------- | ------ | ----- | ---------
Cortex-M0  | 56129  | 828B  | 2460B    
Cortex-M3  | 42644  | 836B  | 2516B    
Cortex-M4F | 42759  | 836B  | 2516B    

## AES128-EAX
This test encrypts and authenticates a 16 byte message,
with 16 bytes additionally authenticated data.  It includes
the initial key schedule.

Core       | Cycles | Stack | Code size
---------- | ------ | ----- | ---------
Cortex-M0  | 49017  | 928B  | 2416B    
Cortex-M3  | 32116  | 924B  | 2396B    
Cortex-M4F | 31445  | 924B  | 2396B    

## AES128-CCM
This test encrypts and authenticates a 16 byte message,
with 16 bytes additionally authenticated data.  It includes
the initial key schedule.

Core       | Cycles | Stack | Code size
---------- | ------ | ----- | ---------
Cortex-M0  | 39593  | 808B  | 2212B    
Cortex-M3  | 26267  | 796B  | 2160B    
Cortex-M4F | 25718  | 796B  | 2160B    

## Chacha20
This test encrypts a 64 byte message.

Core       | Cycles | Stack | Code size
---------- | ------ | ----- | ---------
Cortex-M0  | 5153   | 568B  | 1076B    
Cortex-M3  | 2982   | 560B  | 1056B    
Cortex-M4F | 2952   | 560B  | 1056B    

(For comparison with AES, add an AES256 key schedule plus 4 blocks.
That's about 33K cycles.)

## Salsa20
This test encrypts a 64 byte message.

Core       | Cycles | Stack | Code size
---------- | ------ | ----- | ---------
Cortex-M0  | 5391   | 568B  | 1100B    
Cortex-M3  | 2890   | 564B  | 1004B    
Cortex-M4F | 2839   | 564B  | 1004B    

## SHA256
This test hashes the empty string (one compression function invocation).

Core       | Cycles | Stack | Code size
---------- | ------ | ----- | ---------
Cortex-M0  | 20950  | 460B  | 1396B    
Cortex-M3  | 15020  | 452B  | 1448B    
Cortex-M4F | 14776  | 452B  | 1448B    

## SHA512
This test hashes the empty string (one compression function invocation).

Core       | Cycles | Stack | Code size
---------- | ------ | ----- | ---------
Cortex-M0  | 56085  | 792B  | 2504B    
Cortex-M3  | 42589  | 836B  | 2644B    
Cortex-M4F | 42773  | 836B  | 2644B    

## SHA3-256
This test hashes the empty string (one sponge permutation).

Core       | Cycles | Stack | Code size
---------- | ------ | ----- | ---------
Cortex-M0  | 95509  | 1016B | 1920B    
Cortex-M3  | 74454  | 1008B | 1892B    
Cortex-M4F | 73568  | 1008B | 1892B    

## SHA3-512
This test hashes the empty string (one sponge permutation).

Core       | Cycles | Stack | Code size
---------- | ------ | ----- | ---------
Cortex-M0  | 94942  | 1048B | 1920B    
Cortex-M3  | 74116  | 1040B | 1892B    
Cortex-M4F | 73238  | 1040B | 1892B    

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
