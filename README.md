# Hawk implementation

Hawk is a post-quantum signature scheme, which has a hash-then-sign design and is based on the lattice isomorphism problem. The scheme allows efficient signature generation and verification, even on constrained devices. The signatures and public keys are relatively compact compared to prior post-quantum signature schemes.
This repository was used to provide the code for the on-ramp call for post-quantum signature schemes, organized by NIST.
Specifically, compared to the original Hawk paper [1], this repository contains improvements in terms of efficiency of all algorithms, as well as smaller private key sizes.

**Disclaimer:** *this code was written for the on-ramp call for post-quantum signature schemes, organized by NIST and currently serves research purposes. There was no security review yet so use at own risk*.

The implementations are written in C, using the C99 standard. There is a reference implementation compatible with any processor and an implementation that is optimized for CPUs supporting AVX2.
However, in both cases, the same API is implemented.

The implementation in `src/` is written in C and is configurable at compile-time through macros which are documented in `src/hawk_config.h`; each macro is a boolean option and can be enabled or disabled in `src/hawk_config.h` and/or as a command-line parameter to the compiler. Several implementation strategies are available;

The AVX2 optimized version allows for the compilation flag `HAWK_FMA`. This flag enables the use for FMA ("fused multiply-add") compiler intrinsics for an extra boost to performance. Occasionally (but rarely), use of HAWK_FMA will change the keys and/or signatures generated from a given random seed, impacting reproducibility of test vectors; however, this has no bearing on the security of normal usage.

## Usage

Type `make` to compile: this will generate the reference and AVX2 optimized implementations in their respective directories.
Inside these directories there is a directory `tests` containing multiple tests that can be run.
In particular `tests/speed.c` runs performance benchmarks on Hawk for degrees 256, 512 and 1024.
Note that Hawk-512 and Hawk-1024 provide security level NIST-I and NIST-V respectively, while Hawk-256 is posed as a challenge parameter set.

Applications that want to use Hawk normally work on the external API, which is documented in the `src/hawk.h` file. This is the only file that an external application needs to use. For research purposes, the inner API is documented in `src/hawk_inner.h`. This API gives access to many internal functions that perform some elementary operations used in Hawk. That API also has some non-obvious requirements, such as alignment on temporary buffers, or the need to adjust FPU precision on 32-bit x86 systems.

## Authorship

The Hawk code was written by Thomas Pornin <thomas.pornin@nccgroup.com> and Ludo Pulles <ludo.pulles@cwi.nl>.

## License

This code is provided under the MIT license.

## References

[1] Léo Ducas, Eamonn W. Postlethwaite, Ludo N. Pulles, Wessel van Woerden, Hawk: Module LIP makes Lattice Signatures Fast, Compact and Simple ([ePrint](https://eprint.iacr.org/2022/1155))
