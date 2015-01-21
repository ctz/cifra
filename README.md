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
All measurements performed on an Cortex-M0 (STM32F030F4P6).

## AES
This test does a key schedule, then computes one block.

* **128 bit key**:
    * **Cycles**: 1231000
    * **Stack**: 460B
    * **Code size**: 2256B
* **256 bit key**:
    * **Cycles**: 1698000
    * **Stack**: 476B
    * **Code size**: 2256B

## SHA256
This test hashes the empty string (one compression function invocation).

* **Cycles**: 23000
* **Stack**: 492B
* **Code size**: 1176B

## SHA512
This test hashes the empty string (one compression function invocation).

* **Cycles**: 59000
* **Stack**: 820B
* **Code size**: 2848B

## Curve25519 on Cortex-M0 shootout
Implementation | Optimisation | Cycles      | Code size | Stack usage
-------------- | ------------ | ----------- | --------- | -----------
donna          | `-Os`        | 15748000    | 7.4KB     | 3148B
donna          | `-O2`        | 15218000    | 7.9KB     | 3148B
donna          | `-O3`        | 12907000    | 16KB      | 3380B
naclref        | `-Os`        | 47813000    | 3.2KB     | 4012B
naclref        | `-O2`        | 34309000    | 3.5KB     | 4036B
naclref        | `-O3`        | 35059000    | 4.1KB     | 4044B
tweetnacl      | `-Os`        | 75979000    | 2.8KB     | 2244B
tweetnacl      | `-O2`        | 68876000    | 3.0KB     | 2268B
tweetnacl      | `-O3`        | 69622000    | 8.9KB     | 2900B

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
