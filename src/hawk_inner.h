#ifndef HAWK_INNER_H__
#define HAWK_INNER_H__

/* ==================================================================== */

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "hawk_config.h"

#ifndef HAWK_PREFIX
#define HAWK_PREFIX   hawk
#endif
#define Zh(name)             Zh_(HAWK_PREFIX, name)
#define Zh_(prefix, name)    Zh__(prefix, name)
#define Zh__(prefix, name)   prefix ## _ ## name

#include "hawk.h"

/*
 * MSVC 2015 does not known the C99 keyword 'restrict'.
 */
#if defined _MSC_VER && _MSC_VER
#ifndef restrict
#define restrict   __restrict
#endif
#endif

/* ==================================================================== */
/*
 * Functions imported from NTRUGEN; redeclared here to avoid importing
 * the NTRUGEN inner files.
 */

typedef void (*ntrugen_rng)(void *ctx, void *dst, size_t len);

#define Hawk_keygen   Zh(ntrugen_Hawk_keygen)
int Hawk_keygen(unsigned logn,
	int8_t *restrict f, int8_t *restrict g,
	int8_t *restrict F, int8_t *restrict G,
	int16_t *restrict q00, int16_t *restrict q01, int32_t *restrict q11,
	void *restrict seed, ntrugen_rng rng, void *restrict rng_context,
	void *restrict tmp, size_t tmp_len);

#define Hawk_regen_fg   Zh(ntrugen_Hawk_regen_fg)
void Hawk_regen_fg(unsigned logn,
	int8_t *restrict f, int8_t *restrict g, const void *seed);

/* ==================================================================== */

#ifndef HAWK_AVX2
/*
 * Auto-detection of AVX2 support, if not overridden by configuration.
 */
#if defined __AVX2__ && __AVX2__
#define HAWK_AVX2   1
#else
#define HAWK_AVX2   0
#endif
#endif // HAWK_AVX2

#if HAWK_AVX2
/*
 * This implementation uses AVX2 intrinsics.
 */
#include <immintrin.h>
#if defined __GNUC__ || defined __clang__
#include <x86intrin.h>
#endif
#ifndef HAWK_LE
#define HAWK_LE   1
#endif
#ifndef HAWK_UNALIGNED
#define HAWK_UNALIGNED   1
#endif
#if defined __GNUC__
#define TARGET_AVX2         __attribute__((target("avx2,bmi,pclmul")))
#define TARGET_AVX2_ONLY    __attribute__((target("avx2")))
#define ALIGNED_AVX2   __attribute__((aligned(32)))
#elif defined _MSC_VER && _MSC_VER
#pragma warning( disable : 4752 )
#endif
#endif // HAWK_AVX2

#ifndef TARGET_AVX2
#define TARGET_AVX2
#endif
#ifndef TARGET_AVX2_ONLY
#define TARGET_AVX2_ONLY
#endif
#ifndef ALIGNED_AVX2
#define ALIGNED_AVX2
#endif

/*
 * Disable warning on applying unary minus on an unsigned type.
 */
#if defined _MSC_VER && _MSC_VER
#pragma warning( disable : 4146 )
#pragma warning( disable : 4244 )
#pragma warning( disable : 4267 )
#pragma warning( disable : 4334 )
#endif

/*
 * Auto-detect 64-bit architectures.
 */
#ifndef HAWK_64
#if defined __x86_64__ || defined _M_X64 \
        || defined __ia64 || defined __itanium__ || defined _M_IA64 \
        || defined __powerpc64__ || defined __ppc64__ || defined __PPC64__ \
        || defined __64BIT__ || defined _LP64 || defined __LP64__ \
        || defined __sparc64__ \
        || defined __aarch64__ || defined _M_ARM64 \
        || defined __mips64
#define HAWK_64   1
#else
#define HAWK_64   0
#endif
#endif

/*
 * Auto-detect endianness and support of unaligned accesses.
 */
#if defined __i386__ || defined _M_IX86 \
        || defined __x86_64__ || defined _M_X64 \
	|| defined __aarch64__ || defined _M_ARM64 || defined _M_ARM64EC \
        || (defined _ARCH_PWR8 \
                && (defined __LITTLE_ENDIAN || defined __LITTLE_ENDIAN__))

#ifndef HAWK_LE
#define HAWK_LE   1
#endif
#ifndef HAWK_UNALIGNED
#define HAWK_UNALIGNED   1
#endif

#elif (defined __LITTLE_ENDIAN || defined __LITTLE_ENDIAN__) \
        || (defined __BYTE_ORDER__ && defined __ORDER_LITTLE_ENDIAN__ \
                && __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__)

#ifndef HAWK_LE
#define HAWK_LE   1
#endif
#ifndef HAWK_UNALIGNED
#define HAWK_UNALIGNED   0
#endif

#else

#ifndef HAWK_LE
#define HAWK_LE   0
#endif
#ifndef HAWK_UNALIGNED
#define HAWK_UNALIGNED   0
#endif

#endif

/* No debug output by default. */
#ifndef HAWK_DEBUG
#define HAWK_DEBUG   0
#endif

/* ==================================================================== */

static inline unsigned
dec16le(const void *src)
{
#if HAWK_LE && HAWK_UNALIGNED
	return *(const uint16_t *)src;
#else
	const uint8_t *buf = src;
	return (unsigned)buf[0]
		| ((unsigned)buf[1] << 8);
#endif
}

static inline void
enc16le(void *dst, unsigned x)
{
#if HAWK_LE && HAWK_UNALIGNED
	*(uint16_t *)dst = x;
#else
	uint8_t *buf = dst;
	buf[0] = (uint8_t)x;
	buf[1] = (uint8_t)(x >> 8);
#endif
}

static inline uint32_t
dec32le(const void *src)
{
#if HAWK_LE && HAWK_UNALIGNED
	return *(const uint32_t *)src;
#else
	const uint8_t *buf = src;
	return (uint32_t)buf[0]
		| ((uint32_t)buf[1] << 8)
		| ((uint32_t)buf[2] << 16)
		| ((uint32_t)buf[3] << 24);
#endif
}

static inline void
enc32le(void *dst, uint32_t x)
{
#if HAWK_LE && HAWK_UNALIGNED
	*(uint32_t *)dst = x;
#else
	uint8_t *buf = dst;
	buf[0] = (uint8_t)x;
	buf[1] = (uint8_t)(x >> 8);
	buf[2] = (uint8_t)(x >> 16);
	buf[3] = (uint8_t)(x >> 24);
#endif
}

static inline uint64_t
dec64le(const void *src)
{
#if HAWK_LE && HAWK_UNALIGNED
	return *(const uint64_t *)src;
#else
	const uint8_t *buf = src;
	return (uint64_t)buf[0]
		| ((uint64_t)buf[1] << 8)
		| ((uint64_t)buf[2] << 16)
		| ((uint64_t)buf[3] << 24)
		| ((uint64_t)buf[4] << 32)
		| ((uint64_t)buf[5] << 40)
		| ((uint64_t)buf[6] << 48)
		| ((uint64_t)buf[7] << 56);
#endif
}

static inline void
enc64le(void *dst, uint64_t x)
{
#if HAWK_LE && HAWK_UNALIGNED
	*(uint64_t *)dst = x;
#else
	uint8_t *buf = dst;
	buf[0] = (uint8_t)x;
	buf[1] = (uint8_t)(x >> 8);
	buf[2] = (uint8_t)(x >> 16);
	buf[3] = (uint8_t)(x >> 24);
	buf[4] = (uint8_t)(x >> 32);
	buf[5] = (uint8_t)(x >> 40);
	buf[6] = (uint8_t)(x >> 48);
	buf[7] = (uint8_t)(x >> 56);
#endif
}

/*
 * Extend the top bit (sign bit) of the input into a full word (i.e.
 * result is 0xFFFFFFFF or 0x00000000).
 */
static inline uint32_t
tbmask(uint32_t x)
{
	return (uint32_t)(*(int32_t *)&x >> 31);
}

#if HAWK_DEBUG
/*
 * Debug functions, to print internal values. Do NOT use in production code.
 * The 'u1' variant uses one bit per coefficient.
 */
#include <stdio.h>

static inline void
print_blob(const char *name, const void *data, size_t len)
{
	printf("%s = ", name);
	for (size_t u = 0; u < len; u ++) {
		printf("%02x", ((const uint8_t *)data)[u]);
	}
	printf("\n");
}

static inline void
print_u1(unsigned logn, const char *name, const uint8_t *p)
{
	printf("%s = [%u", name, p[0] & 1);
	size_t n = (size_t)1 << logn;
	for (size_t u = 1; u < n; u ++) {
		printf(",%u", (p[u >> 3] >> (u & 7)) & 1);
	}
	printf("]\n");
}

static inline void
print_i8(unsigned logn, const char *name, const int8_t *p)
{
	printf("%s = [%d", name, p[0]);
	size_t n = (size_t)1 << logn;
	for (size_t u = 1; u < n; u ++) {
		printf(",%d", p[u]);
	}
	printf("]\n");
}

static inline void
print_i16(unsigned logn, const char *name, const int16_t *p)
{
	printf("%s = [%d", name, p[0]);
	size_t n = (size_t)1 << logn;
	for (size_t u = 1; u < n; u ++) {
		printf(",%d", p[u]);
	}
	printf("]\n");
}

static inline void
print_u16(unsigned logn, const char *name, const uint16_t *p)
{
	printf("%s = [%u", name, p[0]);
	size_t n = (size_t)1 << logn;
	for (size_t u = 1; u < n; u ++) {
		printf(",%u", p[u]);
	}
	printf("]\n");
}

static inline void
print_i32(unsigned logn, const char *name, const int32_t *p)
{
	printf("%s = [%ld", name, (long)p[0]);
	size_t n = (size_t)1 << logn;
	for (size_t u = 1; u < n; u ++) {
		printf(",%ld", (long)p[u]);
	}
	printf("]\n");
}

static inline void
print_u32(unsigned logn, const char *name, const uint32_t *p)
{
	printf("%s = [%lu", name, (unsigned long)p[0]);
	size_t n = (size_t)1 << logn;
	for (size_t u = 1; u < n; u ++) {
		printf(",%lu", (unsigned long)p[u]);
	}
	printf("]\n");
}

#endif

/* ==================================================================== */

#endif
