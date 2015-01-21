Cifra
=====
Cifra is a collection of cryptographic primitives.

Aims
----
In order of descending emphasis, cifra aims for:

* *Clarity* and *simplicity*.
* *Countermeasures* for side channel leaks inherent in some
  algorithms.
* Friendlyness for *embedded* use.  Particularly, cifra uses an
  absolute minimum of the standard C library.

Features
--------
* *AES* in the *GCM* and *EAX* authenticated encryption modes.
* *SHA224*, *SHA256*, *SHA384* and *SHA512* hash functions (including *HMAC* and *PBKDF2*).
* *ChaCha20* and *Salsa20* stream ciphers.
* 100% code coverage by line.

Additionally cifra imports *curve25519* from elsewhere for comparison
between various implementations on embedded targets.

TODO
----
* *Poly1305* one-time MAC.
* Constant time *curve25519* for Cortex-M4F using the FPU.
* Constant time *curve25519* for Cortex-M3 (avoiding the variable-time multiplier).
* *Keccak* hash function (aka SHA3).

Testing
-------
There is quite a lot of testing available:

* *Host builds*: run `make test` in the `src` directory.  This builds and
  runs assorted test programs.
* *Emulated embedded builds*: run `make test` in the `src/arm` directory.  This
  expects to find `qemu-system-gnuarmeclipse` on the path.  These tests assume
  a Cortex-M0 target.
* *Cortex-M0 on-target tests*: run `make test.stm32f0` in the `src/arm` directory.
  This expects to find `openocd` on the path, with an STM32F0xx attached via
  stlinkv2.  It uses ARM semihosting to report results.
* *Cortex-M3 on-target tests*: run `make test.stm32f3` as above.

Additionally all embedded targets expect to find the `arm-none-eabi` toolchain
to be on the path.

C library requirements
----------------------
Cifra requires `memcpy`, `memset`, `abort` and `assert`.

License
-------
Public domain.

Author
------
Joseph Birr-Pixton <jpixton@gmail.com>
