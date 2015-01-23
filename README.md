# Cifra
Cifra is a collection of cryptographic primitives.

## Aims
In order of descending emphasis, cifra aims for:

* **Clarity** and **simplicity**.
* Countermeasures for side channel leaks inherent in some
  algorithms.
* Suitablity for embedded use.  Particularly: cifra uses an
  absolute minimum of the standard C library and is reasonably
  efficient with respect to code and data space.

## Features
* **AES** in the **GCM** and **EAX** authenticated encryption modes.
* **SHA224**, **SHA256**, **SHA384** and **SHA512** hash functions (including **HMAC** and **PBKDF2**).
* **ChaCha20** and **Salsa20** stream ciphers.
* 100% code coverage by line.

Additionally cifra imports curve25519 from elsewhere (nacl, tweetnacl,
Adam Langley's donna) for comparison between various implementations
on embedded targets.

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
* **Cortex-M3 on-target tests**: run `make test.stm32f3` as above.

Additionally all embedded targets expect to find the `arm-none-eabi` toolchain
to be on the path.

## Measurements
All measurements performed on an Cortex-M0 (STM32F030F4P6) at `-Os` (optimise
for space).  For reference, the STM32F030F4P6 runs at a maximum clock of 48MHz,
so 1 million cycles is approximately 20 milliseconds.

## AES
This test does a key schedule, then encrypts one block.

* **128 bit key**:
    * **Cycles (key schedule + block)**: 8478
    * **Cycles (key schedule)**: 3412
    * **Cycles (block)**: 5066
    * **Stack**: 312B
    * **Code size**: 1224B

* **256 bit key**:
    * **Cycles (key schedule + block)**: 12415
    * **Cycles (key schedule)**: 5397
    * **Cycles (block)**: 7018
    * **Stack**: 396B
    * **Code size**: 1296B

## AES128-GCM
This test encrypts and authenticates a 16 byte message,
with 16 bytes additionally authenticated data.  It includes
the initial key schedule.

* **Cycles**: 60972
* **Stack**: 820B
* **Code size**: 3500B

## AES128-EAX
This test encrypts and authenticates a 16 byte message,
with 16 bytes additionally authenticated data.  It includes
the initial key schedule.

* **Cycles**: 54409
* **Stack**: 936B
* **Code size**: 3348B

## Chacha20
This test encrypts a 64 byte message.

* **Cycles**: 6871
* **Stack**: 552B
* **Code size**: 1616B

(For comparison with AES, add an AES256 key schedule plus 4 blocks.
That's about 33K cycles.)

## Salsa20
This test encrypts a 64 byte message.

* **Cycles**: 7020
* **Stack**: 552B
* **Code size**: 1624B

## SHA256
This test hashes the empty string (one compression function invocation).

* **Cycles**: 22730
* **Stack**: 460B
* **Code size**: 1776B

## SHA512
This test hashes the empty string (one compression function invocation).

* **Cycles**: 57474
* **Stack**: 780B
* **Code size**: 2844B

## Curve25519 on Cortex-M0 shootout
Implementation | Optimisation | Cycles    | Code size | Stack usage
-------------- | ------------ | --------- | --------- | -----------
donna          | `-Os`        | 15748K    | 7.4KB     | 3148B
donna          | `-O2`        | 15218K    | 7.9KB     | 3148B
donna          | `-O3`        | 12907K    | 16KB      | 3380B
naclref        | `-Os`        | 47813K    | 3.2KB     | 4012B
naclref        | `-O2`        | 34309K    | 3.5KB     | 4036B
naclref        | `-O3`        | 35059K    | 4.1KB     | 4044B
tweetnacl      | `-Os`        | 75979K    | 2.8KB     | 2244B
tweetnacl      | `-O2`        | 68876K    | 3.0KB     | 2268B
tweetnacl      | `-O3`        | 69622K    | 8.9KB     | 2900B

naclref at -O2 seems to give a good balance.  If you can spare the flash,
donna is quite significantly quicker.

## C library requirements
Cifra requires `memcpy`, `memset`, `abort` and `assert`.

## Future
* Poly1305 one-time MAC.
* Constant time curve25519 for Cortex-M4F using the FPU.
* Constant time curve25519 for Cortex-M3 (avoiding the variable-time multiplier).
* Keccak hash function (aka SHA3).

## License
Public domain.

## Author
Joseph Birr-Pixton <jpixton@gmail.com>
