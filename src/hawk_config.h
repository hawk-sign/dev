#ifndef HAWK_CONFIG_H__
#define HAWK_CONFIG_H__

/*
 * AVX2 support. If defined to 1, then this enables use of AVX2 intrinsics,
 * even if the compiler does not explicitly target AVX2-only architectures.
 * Use of AVX2 intrinsics makes the compiled output not compatible with CPUs
 * that do not support AVX2.
 * Defining HAWK_AVX2 to 0 forcibly disables use of AVX2 intrinsics
 * (the compiler might still use AVX2 opcodes as part of its automatic
 * vectorization of loops).
 * If HAWK_AVX2 is not defined here, then use of AVX2 intrinsics will be
 * automatically detected based on the compilation target architecture
 * (e.g. use of the '-mavx2' compiler flag). There is no runtime detection
 * of the abilities of the CPU that actually runs the code.
 *
#define HAWK_AVX2   1
 */

/*
 * Name prefixing. If this macro is defined to a identifier, then all
 * symbols corresponding to non-static functions and global data will
 * have a name starting with that identifier, followed by an underscore.
 * If undefined, then the default prefix is 'hawk'.
 * This is meant to be used for integration into larger applications, to
 * avoid name collisions. Also, the outer application might compile this
 * code twice, with and without AVX2 support, with different name prefixes,
 * and link both versions in the runtime, selecting at runtime which one to
 * call based on the current CPU abilities.
 *
#define HAWK_PREFIX   hawk
 */

#endif
