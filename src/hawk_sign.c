#include "hawk_inner.h"

/*
 * We use computations with polynomials modulo X^n+1 and modulo 18433.
 */
#define Q   18433
#include "modq.h"

#if HAWK_AVX2
/*
 * Binary polynomials (GF(2)[X]); inputs a and b have size N bits;
 * output d has size N or 2*N bits, depending on the operation:
 *
 *    bp_xor_N():     d <- a XOR b
 *    bp_mul_N():     d <- a*b
 *    bp_mulmod_N():  d <- a*b mod X^N+1
 *
 * Multiplications use Karatsuba:
 * If:
 *    a = a0 + a1*(X^(N/2))
 *    b = b0 + b1*(X^(N/2))
 * Then:
 *    d0 <- a0*b0
 *    d1 <- a1*b1
 *    d2 <- (a0 + a1)*(b0 + b1) - d0 - d1
 *    d <- d0 + d1*X^(N/2) + d2*X^N
 * Addition and subtraction are both XOR for binary polynomials; there is
 * no carry, so no need for an extra bit.
 *
 * AVX2-aware systems also support the pclmulq opcode (which appeared with
 * the AES extensions, to support GCM); that opcode computes a 64x64->128
 * binary polynomial multiplication. It words only over the low lanes of
 * registers, so we stick to SSE2 (128-bit registers, not 256-bit).
 *
 * The 'tmp' parameter provided to bp_mulmod_N() is ignored.
 */

TARGET_AVX2
static inline void
bp_xor_256(uint8_t *d, const uint8_t *a, const uint8_t *b)
{
	__m256i ya = _mm256_loadu_si256((const __m256i *)a);
	__m256i yb = _mm256_loadu_si256((const __m256i *)b);
	_mm256_storeu_si256((__m256i *)d, _mm256_xor_si256(ya, yb));
}

TARGET_AVX2
static inline void
bp_xor_512(uint8_t *d, const uint8_t *a, const uint8_t *b)
{
	__m256i ya0 = _mm256_loadu_si256((const __m256i *)a + 0);
	__m256i ya1 = _mm256_loadu_si256((const __m256i *)a + 1);
	__m256i yb0 = _mm256_loadu_si256((const __m256i *)b + 0);
	__m256i yb1 = _mm256_loadu_si256((const __m256i *)b + 1);
	_mm256_storeu_si256((__m256i *)d + 0, _mm256_xor_si256(ya0, yb0));
	_mm256_storeu_si256((__m256i *)d + 1, _mm256_xor_si256(ya1, yb1));
}

TARGET_AVX2
static inline void
bp_xor_1024(uint8_t *d, const uint8_t *a, const uint8_t *b)
{
	__m256i ya0 = _mm256_loadu_si256((const __m256i *)a + 0);
	__m256i ya1 = _mm256_loadu_si256((const __m256i *)a + 1);
	__m256i ya2 = _mm256_loadu_si256((const __m256i *)a + 2);
	__m256i ya3 = _mm256_loadu_si256((const __m256i *)a + 3);
	__m256i yb0 = _mm256_loadu_si256((const __m256i *)b + 0);
	__m256i yb1 = _mm256_loadu_si256((const __m256i *)b + 1);
	__m256i yb2 = _mm256_loadu_si256((const __m256i *)b + 2);
	__m256i yb3 = _mm256_loadu_si256((const __m256i *)b + 3);
	_mm256_storeu_si256((__m256i *)d + 0, _mm256_xor_si256(ya0, yb0));
	_mm256_storeu_si256((__m256i *)d + 1, _mm256_xor_si256(ya1, yb1));
	_mm256_storeu_si256((__m256i *)d + 2, _mm256_xor_si256(ya2, yb2));
	_mm256_storeu_si256((__m256i *)d + 3, _mm256_xor_si256(ya3, yb3));
}

TARGET_AVX2
static inline void
bp_mul_256(__m128i *xd, const __m128i *xa, const __m128i *xb)
{
	/* (e0, e1, e2) <- (a0l*b0l, a0h*b0h, a0l*b0h + a0h*b0l) */
	__m128i xe0 = _mm_clmulepi64_si128(xa[0], xb[0], 0x00);
	__m128i xe1 = _mm_clmulepi64_si128(xa[0], xb[0], 0x11);
	__m128i xe2 = _mm_xor_si128(
		_mm_clmulepi64_si128(xa[0], xb[0], 0x01),
		_mm_clmulepi64_si128(xa[0], xb[0], 0x10));

	/* (f0, f1, f2) <- (a1l*b1l, a1h*b1h, a1l*b1h + a1h*b1l) */
	__m128i xf0 = _mm_clmulepi64_si128(xa[1], xb[1], 0x00);
	__m128i xf1 = _mm_clmulepi64_si128(xa[1], xb[1], 0x11);
	__m128i xf2 = _mm_xor_si128(
		_mm_clmulepi64_si128(xa[1], xb[1], 0x01),
		_mm_clmulepi64_si128(xa[1], xb[1], 0x10));

	/* (u, v) <- (a0 + a1, b0 + b1)
	   (g0, g1, g2) <- (ul*vl, uh*vh, ul*vh + uh*bl */
	__m128i xaa = _mm_xor_si128(xa[0], xa[1]);
	__m128i xbb = _mm_xor_si128(xb[0], xb[1]);
	__m128i xg0 = _mm_clmulepi64_si128(xaa, xbb, 0x00);
	__m128i xg1 = _mm_clmulepi64_si128(xaa, xbb, 0x11);
	__m128i xg2 = _mm_xor_si128(
		_mm_clmulepi64_si128(xaa, xbb, 0x01),
		_mm_clmulepi64_si128(xaa, xbb, 0x10));

	/* a0*b0 = e0 + e2*X^64 + e1*X^128
	   a1*b1 = f0 + f2*X^64 + f1*X^128
	   a0*b1 + a1*b0 = g0 + g2*X^64 + g1*X^128 + a0*b0 + a1*b1 */
	__m128i xhh = _mm_xor_si128(xe1, xf0);
	__m128i xjj = _mm_xor_si128(xg2, _mm_xor_si128(xe2, xf2));
	xd[0] = _mm_xor_si128(xe0, _mm_bslli_si128(xe2, 8));
	xd[1] = _mm_xor_si128(
		_mm_xor_si128(xe0, xhh),
		_mm_xor_si128(xg0, _mm_alignr_epi8(xjj, xe2, 8)));
	xd[2] = _mm_xor_si128(
		_mm_xor_si128(xhh, xf1),
		_mm_xor_si128(xg1, _mm_alignr_epi8(xf2, xjj, 8)));
	xd[3] = _mm_xor_si128(xf1, _mm_bsrli_si128(xf2, 8));
}

TARGET_AVX2
static void
bp_mul_512(__m128i *xd, const __m128i *xa, const __m128i *xb)
{
	__m128i xaa[2], xbb[2], xe[4], xf[4], xg[4];
	bp_mul_256(xe, xa, xb);
	bp_mul_256(xf, xa + 2, xb + 2);
	for (int i = 0; i < 2; i ++) {
		xaa[i] = _mm_xor_si128(xa[i], xa[i + 2]);
		xbb[i] = _mm_xor_si128(xb[i], xb[i + 2]);
	}
	bp_mul_256(xg, xaa, xbb);
	for (int i = 0; i < 4; i ++) {
		xg[i] = _mm_xor_si128(xg[i], _mm_xor_si128(xe[i], xf[i]));
	}
	xd[0] = xe[0];
	xd[1] = xe[1];
	xd[2] = _mm_xor_si128(xe[2], xg[0]);
	xd[3] = _mm_xor_si128(xe[3], xg[1]);
	xd[4] = _mm_xor_si128(xf[0], xg[2]);
	xd[5] = _mm_xor_si128(xf[1], xg[3]);
	xd[6] = xf[2];
	xd[7] = xf[3];
}

TARGET_AVX2
static void
bp_mul_1024(__m128i *xd, const __m128i *xa, const __m128i *xb)
{
	__m128i xaa[4], xbb[4], xe[8], xf[8], xg[8];
	bp_mul_512(xe, xa, xb);
	bp_mul_512(xf, xa + 4, xb + 4);
	for (int i = 0; i < 4; i ++) {
		xaa[i] = _mm_xor_si128(xa[i], xa[i + 4]);
		xbb[i] = _mm_xor_si128(xb[i], xb[i + 4]);
	}
	bp_mul_512(xg, xaa, xbb);
	for (int i = 0; i < 8; i ++) {
		xg[i] = _mm_xor_si128(xg[i], _mm_xor_si128(xe[i], xf[i]));
	}
	for (int i = 0; i < 4; i ++) {
		xd[i] = xe[i];
	}
	for (int i = 4; i < 8; i ++) {
		xd[i] = _mm_xor_si128(xe[i], xg[i - 4]);
	}
	for (int i = 8; i < 12; i ++) {
		xd[i] = _mm_xor_si128(xf[i - 8], xg[i - 4]);
	}
	for (int i = 12; i < 16; i ++) {
		xd[i] = xf[i - 8];
	}
}

TARGET_AVX2
static void
bp_mulmod_256(uint8_t *d, const uint8_t *a, const uint8_t *b, uint8_t *tmp)
{
	(void)tmp;
	__m128i xa[2], xb[2], xd[4];
	xa[0] = _mm_loadu_si128((const __m128i *)a + 0);
	xa[1] = _mm_loadu_si128((const __m128i *)a + 1);
	xb[0] = _mm_loadu_si128((const __m128i *)b + 0);
	xb[1] = _mm_loadu_si128((const __m128i *)b + 1);
	bp_mul_256(xd, xa, xb);
	_mm_storeu_si128((__m128i *)d + 0, _mm_xor_si128(xd[0], xd[2]));
	_mm_storeu_si128((__m128i *)d + 1, _mm_xor_si128(xd[1], xd[3]));
}

TARGET_AVX2
static void
bp_mulmod_512(uint8_t *d, const uint8_t *a, const uint8_t *b, uint8_t *tmp)
{
	(void)tmp;
	__m128i xa[4], xb[4], xd[8];
	for (int i = 0; i < 4; i ++) {
		xa[i] = _mm_loadu_si128((const __m128i *)a + i);
		xb[i] = _mm_loadu_si128((const __m128i *)b + i);
	}
	bp_mul_512(xd, xa, xb);
	for (int i = 0; i < 4; i ++) {
		_mm_storeu_si128((__m128i *)d + i,
			_mm_xor_si128(xd[i], xd[i + 4]));
	}
}

TARGET_AVX2
static void
bp_mulmod_1024(uint8_t *d, const uint8_t *a, const uint8_t *b, uint8_t *tmp)
{
	(void)tmp;
	__m128i xa[8], xb[8], xd[16];
	for (int i = 0; i < 8; i ++) {
		xa[i] = _mm_loadu_si128((const __m128i *)a + i);
		xb[i] = _mm_loadu_si128((const __m128i *)b + i);
	}
	bp_mul_1024(xd, xa, xb);
	for (int i = 0; i < 8; i ++) {
		_mm_storeu_si128((__m128i *)d + i,
			_mm_xor_si128(xd[i], xd[i + 8]));
	}
}

/*
 * Reduce a polynomial modulo 2 (output f2 is n/8 bytes = n bits).
 */
TARGET_AVX2
static void
extract_lowbit(unsigned logn, uint8_t *f2, const int8_t *f)
{
	size_t n = (size_t)1 << logn;
	for (size_t u = 0; u < n; u += 32) {
		__m256i x = _mm256_loadu_si256((const __m256i *)(f + u));
		x = _mm256_slli_epi16(x, 7);
		*(uint32_t *)(f2 + (u >> 3)) = _mm256_movemask_epi8(x);
	}
}

#else // HAWK_AVX2
/*
 * Binary polynomials (GF(2)[X]); inputs a and b have size N bits;
 * output d has size N or 2*N bits, depending on the operation:
 *
 *    bp_xor_N():     d <- a XOR b
 *    bp_mul_N():     d <- a*b
 *    bp_muladd_N():  d <- d + a*b
 *    bp_mulmod_N():  d <- a*b mod X^N+1
 *
 * Multiplications use Karatsuba:
 * If:
 *    a = a0 + a1*(X^(N/2))
 *    b = b0 + b1*(X^(N/2))
 * Then:
 *    d0 <- a0*b0
 *    d1 <- a1*b1
 *    d2 <- (a0 + a1)*(b0 + b1) - d0 - d1
 *    d <- d0 + d1*X^(N/2) + d2*X^N
 * Addition and subtraction are both XOR for binary polynomials; there is
 * no carry, so no need for an extra bit.
 *
 * bp_muladd_N() may use up to 4*N bits in the provided 'tmp' buffer.
 * bp_modadd_N() may use up to 3*N bits in the provided 'tmp' buffer.
 */

/*
 * Multiplication of two binary polynomials ("carryless multiplication")
 * of degree less than 32, result has degree less than 64.
 */
static uint64_t
bp_mul_32(uint32_t x, uint32_t y)
{
	/*
	 * Classic technique (rediscovered many times): integer
	 * multiplications with "holes" to absorb unwanted carries.
	 */
	uint32_t x0 = x & 0x11111111;
	uint32_t x1 = x & 0x22222222;
	uint32_t x2 = x & 0x44444444;
	uint32_t x3 = x & 0x88888888;

	uint32_t y0 = y & 0x11111111;
	uint32_t y1 = y & 0x22222222;
	uint32_t y2 = y & 0x44444444;
	uint32_t y3 = y & 0x88888888;

#define M(a, b)   ((uint64_t)(a) * (uint64_t)(b))

	uint64_t z0 = M(x0, y0) ^ M(x1, y3) ^ M(x2, y2) ^ M(x3, y1);
	uint64_t z1 = M(x0, y1) ^ M(x1, y0) ^ M(x2, y3) ^ M(x3, y2);
	uint64_t z2 = M(x0, y2) ^ M(x1, y1) ^ M(x2, y0) ^ M(x3, y3);
	uint64_t z3 = M(x0, y3) ^ M(x1, y2) ^ M(x2, y1) ^ M(x3, y0);

#undef M

	z0 &= (uint64_t)0x1111111111111111;
	z1 &= (uint64_t)0x2222222222222222;
	z2 &= (uint64_t)0x4444444444444444;
	z3 &= (uint64_t)0x8888888888888888;
	return z0 | z1 | z2 | z3;
}

static inline void
bp_xor_64(uint8_t *d, const uint8_t *a, const uint8_t *b)
{
#if HAWK_UNALIGNED
	*(uint64_t *)d = *(const uint64_t *)a ^ *(const uint64_t *)b;
#else
	for (size_t u = 0; u < 8; u ++) {
		d[u] = a[u] ^ b[u];
	}
#endif
}

static inline void
bp_xor_128(uint8_t *d, const uint8_t *a, const uint8_t *b)
{
#if HAWK_UNALIGNED
	const uint64_t *aq = (uint64_t *)a;
	const uint64_t *bq = (uint64_t *)b;
	uint64_t *dq = (uint64_t *)d;
	for (size_t u = 0; u < 2; u ++) {
		dq[u] = aq[u] ^ bq[u];
	}
#else
	for (size_t u = 0; u < 16; u ++) {
		d[u] = a[u] ^ b[u];
	}
#endif
}

static inline void
bp_xor_256(uint8_t *d, const uint8_t *a, const uint8_t *b)
{
#if HAWK_UNALIGNED
	const uint64_t *aq = (uint64_t *)a;
	const uint64_t *bq = (uint64_t *)b;
	uint64_t *dq = (uint64_t *)d;
	for (size_t u = 0; u < 4; u ++) {
		dq[u] = aq[u] ^ bq[u];
	}
#else
	for (size_t u = 0; u < 32; u ++) {
		d[u] = a[u] ^ b[u];
	}
#endif
}

static inline void
bp_xor_512(uint8_t *d, const uint8_t *a, const uint8_t *b)
{
#if HAWK_UNALIGNED
	const uint64_t *aq = (uint64_t *)a;
	const uint64_t *bq = (uint64_t *)b;
	uint64_t *dq = (uint64_t *)d;
	for (size_t u = 0; u < 8; u ++) {
		dq[u] = aq[u] ^ bq[u];
	}
#else
	for (size_t u = 0; u < 64; u ++) {
		d[u] = a[u] ^ b[u];
	}
#endif
}

static inline void
bp_xor_1024(uint8_t *d, const uint8_t *a, const uint8_t *b)
{
#if HAWK_UNALIGNED
	const uint64_t *aq = (uint64_t *)a;
	const uint64_t *bq = (uint64_t *)b;
	uint64_t *dq = (uint64_t *)d;
	for (size_t u = 0; u < 16; u ++) {
		dq[u] = aq[u] ^ bq[u];
	}
#else
	for (size_t u = 0; u < 128; u ++) {
		d[u] = a[u] ^ b[u];
	}
#endif
}

static void
bp_muladd_64(uint8_t *restrict d, const uint8_t *restrict a,
	const uint8_t *restrict b, uint8_t *restrict tmp)
{
	(void)tmp;

	uint32_t a0 = dec32le(a);
	uint32_t a1 = dec32le(a + 4);
	uint32_t b0 = dec32le(b);
	uint32_t b1 = dec32le(b + 4);

	uint64_t c0 = bp_mul_32(a0, b0);
	uint64_t c1 = bp_mul_32(a1, b1);
	uint64_t c2 = bp_mul_32(a0 ^ a1, b0 ^ b1) ^ c0 ^ c1;

	enc64le(d, dec64le(d) ^ c0 ^ (c2 << 32));
	enc64le(d + 8, dec64le(d + 8) ^ c1 ^ (c2 >> 32));
}

#define MKBP_MULADD(n, hn)    MKBP_MULADD_(n, hn)
#define MKBP_MULADD_(n, hn) \
static void \
bp_muladd_ ## n(uint8_t *restrict d, const uint8_t *restrict a, \
	const uint8_t *restrict b, uint8_t *restrict tmp) \
{ \
	uint8_t *t1 = tmp; \
	uint8_t *t2 = t1 + (n / 8); \
	uint8_t *t3 = t2 + (n / 8); \
	/* t1 <- (a0 + a1)*(b0 + b1) + d0 + d1 */ \
	bp_xor_ ## hn(t2, a, a + (hn / 8)); \
	bp_xor_ ## hn(t2 + (hn / 8), b, b + (hn / 8)); \
	bp_xor_ ## n(t1, d, d + (n / 8)); \
	bp_muladd_ ## hn(t1, t2, t2 + (hn / 8), t3); \
	/* d0 <- d0 + a0*b0 */ \
	bp_muladd_ ## hn(d, a, b, t2); \
	/* d1 <- d1 + a1*b1 */ \
	bp_muladd_ ## hn(d + (n / 8), a + (hn / 8), b + (hn / 8), t2); \
	/* t1 <- t1 + d0 + d1 = a0*b1 + a1*b0 */ \
	bp_xor_ ## n(t1, t1, d); \
	bp_xor_ ## n(t1, t1, d + (n / 8)); \
	/* d <- d + (x^{n/2})*t1 */ \
	bp_xor_ ## n(d + (hn / 8), d + (hn / 8), t1); \
}

MKBP_MULADD(128, 64)
MKBP_MULADD(256, 128)
MKBP_MULADD(512, 256)

#define MKBP_MULMOD(n, hn)    MKBP_MULMOD_(n, hn)
#define MKBP_MULMOD_(n, hn) \
static void \
bp_mulmod_ ## n(uint8_t *restrict d, const uint8_t *restrict a, \
	const uint8_t *restrict b, uint8_t *restrict tmp) \
{ \
	uint8_t *t1 = tmp; \
	uint8_t *t2 = t1 + (n / 8); \
	/* t1 <- (a0 + a1)*(b0 + b1) */ \
	bp_xor_ ## hn(d, a, a + (hn / 8)); \
	bp_xor_ ## hn(d + (hn / 8), b, b + (hn / 8)); \
	memset(t1, 0, (n / 8)); \
	bp_muladd_ ## hn(t1, d, d + (hn / 8), t2); \
	/* d <- a0*b0 + a1*b1 */ \
	memset(d, 0, (n / 8)); \
	bp_muladd_ ## hn(d, a, b, t2); \
	bp_muladd_ ## hn(d, a + (hn / 8), b + (hn / 8), t2); \
	/* t1 <- t1 + d = a0*b1 + a1*b0 */ \
	bp_xor_ ## n(t1, t1, d); \
	/* d <- d + rotate_{n/2}(t1) */ \
	bp_xor_ ## hn(d, d, t1 + (hn / 8)); \
	bp_xor_ ## hn(d + (hn / 8), d + (hn / 8), t1); \
}

MKBP_MULMOD(256, 128)
MKBP_MULMOD(512, 256)
MKBP_MULMOD(1024, 512)

/*
 * Reduce a polynomial modulo 2 (output f2 is n/8 bytes = n bits).
 */
static void
extract_lowbit(unsigned logn, uint8_t *f2, const int8_t *f)
{
	size_t n = (size_t)1 << logn;
	const uint8_t *fu = (const uint8_t *)f;
	for (size_t u = 0; u < n; u += 8) {
		f2[u >> 3] = (fu[u + 0] & 1)
			| ((fu[u + 1] & 1) << 1)
			| ((fu[u + 2] & 1) << 2)
			| ((fu[u + 3] & 1) << 3)
			| ((fu[u + 4] & 1) << 4)
			| ((fu[u + 5] & 1) << 5)
			| ((fu[u + 6] & 1) << 6)
			| ((fu[u + 7] & 1) << 7);
	}
}

#endif // HAWK_AVX2

/*
 * (t0, t1) <- B*h  (mod 2)
 * B = [[f F],[g G]]
 * Only the low bit of each coefficient of f, g, F and G is provided;
 * parameters f2, g2, F2 and G2 are arrays of n/8 bytes (n bits) each.
 * Inputs h0, h1 and outputs t0, t1 are also arrays of n/8 bytes.
 *
 * tmp usage: at most n/2 bytes (4*n bits)
 */
static void
basis_m2_mul(unsigned logn, uint8_t *restrict t0, uint8_t *restrict t1,
	const uint8_t *restrict h0, const uint8_t *restrict h1,
	const uint8_t *restrict f2, const uint8_t *restrict g2,
	const uint8_t *restrict F2, const uint8_t *restrict G2,
	uint8_t *tmp)
{
	/*
	 * t0 = f*h0 + F*h1
	 * t1 = g*h0 + G*h1
	 */
	size_t n = (size_t)1 << logn;
	uint8_t *w1 = tmp;
	uint8_t *w2 = w1 + (n >> 3);
	switch (logn) {
	case 8:
		bp_mulmod_256(t0, h0, f2, w2);
		bp_mulmod_256(w1, h1, F2, w2);
		bp_xor_256(t0, t0, w1);
		bp_mulmod_256(t1, h0, g2, w2);
		bp_mulmod_256(w1, h1, G2, w2);
		bp_xor_256(t1, t1, w1);
		break;
	case 9:
		bp_mulmod_512(t0, h0, f2, w2);
		bp_mulmod_512(w1, h1, F2, w2);
		bp_xor_512(t0, t0, w1);
		bp_mulmod_512(t1, h0, g2, w2);
		bp_mulmod_512(w1, h1, G2, w2);
		bp_xor_512(t1, t1, w1);
		break;
	case 10:
		bp_mulmod_1024(t0, h0, f2, w2);
		bp_mulmod_1024(w1, h1, F2, w2);
		bp_xor_1024(t0, t0, w1);
		bp_mulmod_1024(t1, h0, g2, w2);
		bp_mulmod_1024(w1, h1, G2, w2);
		bp_xor_1024(t1, t1, w1);
		break;
	}
}

/*
 * Tables for the Gaussian sampler: we have two distributions over 2*Z,
 * with the same standard deviation 2*sigma. Given:
 *    p(x) = exp(-(x^2) / 2*(2*sigma)^2)
 * Then, for integers k:
 *    D0(2*k) = p(2*k) / \sum_j p(2*j)
 *    D1(2*k) = p(2*k-1) / \sum_j p(2*j-1)
 * D0 is centred on 0, while D1 is centred on 1. Both distributions only
 * return even integers.
 *
 * Let P0(x) = P(|X0| >= x)  (with X0 selected with distribution D0).
 * Let P1(x) = P(|X1| >= x)  (with X1 selected with distribution D1).
 * For integers k >= 0, we define the table T:
 *    T[2*k]   = floor(P0(2*(k+1)) * 2^78)
 *    T[2*k+1] = floor(P1(2*(k+1)+1) * 2^78)
 * Each 78-bit value is split into a high part ("hi") of 15 bits, and
 * a low part ("lo") of 63 bits.
 */

static const uint16_t sig_gauss_hi_Hawk_256[] = {
	0x4D70, 0x268B,
	0x0F80, 0x04FA,
	0x0144, 0x0041,
	0x000A, 0x0001
};
#define SG_MAX_HI_Hawk_256  ((sizeof sig_gauss_hi_Hawk_256) / sizeof(uint16_t))

ALIGNED_AVX2
static const uint64_t sig_gauss_lo_Hawk_256[] = {
	0x71FBD58485D45050, 0x1408A4B181C718B1,
	0x54114F1DC2FA7AC9, 0x614569CC54722DC9,
	0x42F74ADDA0B5AE61, 0x151C5CDCBAFF49A3,
	0x252E2152AB5D758B, 0x23460C30AC398322,
	0x0FDE62196C1718FC, 0x01355A8330C44097,
	0x00127325DDF8CEBA, 0x0000DC8DE401FD12,
	0x000008100822C548, 0x0000003B0FFB28F0,
	0x0000000152A6E9AE, 0x0000000005EFCD99,
	0x000000000014DA4A, 0x0000000000003953,
	0x000000000000007B, 0x0000000000000000
};
#define SG_MAX_LO_Hawk_256  ((sizeof sig_gauss_lo_Hawk_256) / sizeof(uint64_t))

static const uint16_t sig_gauss_hi_Hawk_512[] = {
	0x580B, 0x35F9,
	0x1D34, 0x0DD7,
	0x05B7, 0x020C,
	0x00A2, 0x002B,
	0x000A, 0x0001
};
#define SG_MAX_HI_Hawk_512  ((sizeof sig_gauss_hi_Hawk_512) / sizeof(uint16_t))

ALIGNED_AVX2
static const uint64_t sig_gauss_lo_Hawk_512[] = {
	0x0C27920A04F8F267, 0x3C689D9213449DC9,
	0x1C4FF17C204AA058, 0x7B908C81FCE3524F,
	0x5E63263BE0098FFD, 0x4EBEFD8FF4F07378,
	0x56AEDFB0876A3BD8, 0x4628BC6B23887196,
	0x061E21D588CC61CC, 0x7F769211F07B326F,
	0x2BA568D92EEC18E7, 0x0668F461693DFF8F,
	0x00CF0F8687D3B009, 0x001670DB65964485,
	0x000216A0C344EB45, 0x00002AB6E11C2552,
	0x000002EDF0B98A84, 0x0000002C253C7E81,
	0x000000023AF3B2E7, 0x0000000018C14ABF,
	0x0000000000EBCC6A, 0x000000000007876E,
	0x00000000000034CF, 0x000000000000013D,
	0x0000000000000006, 0x0000000000000000
};
#define SG_MAX_LO_Hawk_512  ((sizeof sig_gauss_lo_Hawk_512) / sizeof(uint64_t))

static const uint16_t sig_gauss_hi_Hawk_1024[] = {
	0x58B0, 0x36FE,
	0x1E3A, 0x0EA0,
	0x0632, 0x024A,
	0x00BC, 0x0034,
	0x000C, 0x0002
};
#define SG_MAX_HI_Hawk_1024 ((sizeof sig_gauss_hi_Hawk_1024) / sizeof(uint16_t))

ALIGNED_AVX2
static const uint64_t sig_gauss_lo_Hawk_1024[] = {
	0x3AAA2EB76504E560, 0x01AE2B17728DF2DE,
	0x70E1C03E49BB683E, 0x6A00B82C69624C93,
	0x55CDA662EF2D1C48, 0x2685DB30348656A4,
	0x31E874B355421BB7, 0x430192770E205503,
	0x57C0676C029895A7, 0x5353BD4091AA96DB,
	0x3D4D67696E51F820, 0x09915A53D8667BEE,
	0x014A1A8A93F20738, 0x0026670030160D5F,
	0x0003DAF47E8DFB21, 0x0000557CD1C5F797,
	0x000006634617B3FF, 0x0000006965E15B13,
	0x00000005DBEFB646, 0x0000000047E9AB38,
	0x0000000002F93038, 0x00000000001B2445,
	0x000000000000D5A7, 0x00000000000005AA,
	0x0000000000000021, 0x0000000000000000
};
#define SG_MAX_LO_Hawk_1024 ((sizeof sig_gauss_lo_Hawk_1024) / sizeof(uint64_t))

/*
 * Generate x with the right Gaussian, for the specified parity bits.
 * x is formally generated with center t/2 and standard deviation sigma_sign
 * (with sigma_sign = 1.010, 1.278 or 1.299, depending on degree); this
 * function generates 2*x.
 *
 * Returned value is the squared norm of x.
 *
 * Internally, a random 40-byte seed is obtained from the RNG, to initialize
 * (along with a counter) four internal SHAKE instances. If sc_extra is not
 * NULL, then it should be a non-flipped SHAKE context which will be used
 * as basis for the four instances; otherwise, empty contexts will be used.
 */
TARGET_AVX2
static uint32_t
sig_gauss(unsigned logn,
	void (*rng)(void *ctx, void *dst, size_t len), void *rng_context,
	const shake_context *sc_extra, int8_t *x, const uint8_t *t)
{
	const uint16_t *tab_hi;
	const uint64_t *tab_lo;
	size_t hi_len, lo_len;

	switch (logn) {
	case 8:
		tab_hi = sig_gauss_hi_Hawk_256;
		tab_lo = sig_gauss_lo_Hawk_256;
		hi_len = SG_MAX_HI_Hawk_256;
		lo_len = SG_MAX_LO_Hawk_256;
		break;
	case 9:
		tab_hi = sig_gauss_hi_Hawk_512;
		tab_lo = sig_gauss_lo_Hawk_512;
		hi_len = SG_MAX_HI_Hawk_512;
		lo_len = SG_MAX_LO_Hawk_512;
		break;
	default: /* 10 */
		tab_hi = sig_gauss_hi_Hawk_1024;
		tab_lo = sig_gauss_lo_Hawk_1024;
		hi_len = SG_MAX_HI_Hawk_1024;
		lo_len = SG_MAX_LO_Hawk_1024;
		break;
	}

	/*
	 * We produce 2*n samples. Each sample requires two elements
	 * from the RNG: a low part (64 bits) and a high part (16 bits).
	 * A SHAKE instance produces 64-bit words in groups of five
	 * (little-endian encoding is assumed); the first four words are
	 * the low parts for four samples (lo0, lo1, lo2 and lo3), and the
	 * fifth word contains the high parts for the four samples
	 * (hi0 + (hi1 << 16) + (hi2 << 32) + (hi3 << 48)).
	 *
	 * We formally use four parallel SHAKE instances, instantiated
	 * over seeds obtained from the source RNG. For j = 0 to 3,
	 * instance j produces samples of index 16*i + 4*j + k, with
	 * k = 0, 1, 2 or 3. A small, RAM-constrained implementation
	 * will use the four instances sequentially, reusing the space
	 * for the SHAKE context; a large system with vector instructions
	 * (e.g. AVX2) might run the four SHAKE instances at the same time.
	 */
	size_t n = (size_t)1 << logn;
	uint8_t seed[41];
	rng(rng_context, seed, 40);
#if HAWK_AVX2

	/*
	 * Prepare tables. We want to pre-expand values into AVX2
	 * registers, and also to have fixed-length tables so that the
	 * compiler can unroll loops where appropriate. Fortunately,
	 * the tables for n=512 and n=1024 have the same length (this is
	 * slightly suboptimal for n=256, which has smaller tables).
	 */
	__m256i ytab_hi[10];
	__m256i ytab_lo[26];
	for (size_t i = 0; i < hi_len; i ++) {
		ytab_hi[i] = _mm256_set1_epi64x(tab_hi[i]);
	}
	for (size_t i = hi_len; i < 10; i ++) {
		ytab_hi[i] = _mm256_setzero_si256();
	}
	for (size_t i = 0; i < lo_len; i ++) {
		ytab_lo[i] = _mm256_set1_epi64x(tab_lo[i]);
	}
	for (size_t i = lo_len; i < 26; i ++) {
		ytab_lo[i] = _mm256_setzero_si256();
	}

	/*
	 * Prepare the four parallel SHAKE contexts.
	 */
	shake_context sc[4];
	for (int i = 0; i < 4; i ++) {
		if (sc_extra != NULL) {
			sc[i] = *sc_extra;
		} else {
			shake_init(&sc[i], 256);
		}
		seed[40] = (uint8_t)i;
		shake_inject(&sc[i], seed, 41);
	}
	shake_x4_context scx4;
	shake_x4_flip(&scx4, sc);

	__m256i y15 = _mm256_set1_epi64x(0x7FFF);
	__m256i y63 = _mm256_set1_epi64x(0x7FFFFFFFFFFFFFFF);

	/*
	 * Squared norm: we accumulate 16 parallel sums.
	 * Each sum can accumulate up to 128 values (for degree n = 1024,
	 * we sample 2048 values, and 2048/16 = 128) and each value
	 * can be up to 26^2, for a total of 93312, which does not fit
	 * in 16 bits. It is extremely improbable that we ever reach that
	 * value (since extreme values of coefficients of x are very
	 * improbable) but, for completeness, we move the partial sums
	 * at mid-course (when moving from x0 to x1) so that such counters
	 * fit in 16 bits each.
	 */
	__m256i ysn1 = _mm256_setzero_si256();
	__m256i ysn2 = _mm256_setzero_si256();

	/*
	 * Sample values by chunks of 16.
	 */
	for (size_t u = 0; u < (n << 1); u += 16) {
		/*
		 * Get 16*10 bytes from the parallel SHAKE instances.
		 */
		union {
			__m256i y[5];
			uint64_t q[20];
		} buf;
		shake_x4_extract_words(&scx4, buf.q, 5);
		__m256i yhi_src = buf.y[4];
		uint64_t tb0 = (uint64_t)t[(u >> 3) + 0] << 31;
		uint64_t tb1 = tb0 >> 4;
		uint64_t tb2 = (uint64_t)t[(u >> 3) + 1] << 31;
		uint64_t tb3 = tb2 >> 4;
		__m256i ypb = _mm256_setr_epi64x(tb0, tb1, tb2, tb3);

		__m256i yxx = _mm256_setzero_si256();
		for (size_t k = 0; k < 4; k ++) {
			__m256i ylo = buf.y[k];
			__m256i yhi = _mm256_and_si256(yhi_src, y15);
			yhi_src = _mm256_srli_epi64(yhi_src, 16);

			/* Extract sign bit. */
			__m256i yneg = _mm256_shuffle_epi32(
				_mm256_srai_epi32(ylo, 31), 0xF5);
			ylo = _mm256_and_si256(ylo, y63);

			/* Use even or odd column depending on
			   parity of t. */
			__m256i yodd = _mm256_shuffle_epi32(
				_mm256_srai_epi32(ypb, 31), 0xA0);
			ypb = _mm256_srli_epi64(ypb, 1);

			__m256i yr = _mm256_setzero_si256();
			for (size_t i = 0; i < 10; i += 2) {
				__m256i ytlo = _mm256_or_si256(
					_mm256_andnot_si256(yodd, ytab_lo[i]),
					_mm256_and_si256(yodd, ytab_lo[i + 1]));
				__m256i ycc = _mm256_srli_epi64(
					_mm256_sub_epi64(ylo, ytlo), 63);
				__m256i ythi = _mm256_or_si256(
					_mm256_andnot_si256(yodd, ytab_hi[i]),
					_mm256_and_si256(yodd, ytab_hi[i + 1]));
				yr = _mm256_add_epi32(yr, _mm256_srli_epi32(
					_mm256_sub_epi32(_mm256_sub_epi32(
						yhi, ythi), ycc), 31));
			}
			__m256i yhinz = _mm256_cmpeq_epi32(
				yhi, _mm256_setzero_si256());
			for (size_t i = 10; i < 26; i += 2) {
				__m256i ytlo = _mm256_or_si256(
					_mm256_andnot_si256(yodd, ytab_lo[i]),
					_mm256_and_si256(yodd, ytab_lo[i + 1]));
				__m256i ycc = _mm256_srli_epi64(
					_mm256_sub_epi64(ylo, ytlo), 63);
				yr = _mm256_add_epi32(yr,
					_mm256_and_si256(yhinz, ycc));
			}

			/* Multiply by 2 and apply parity. */
			yr = _mm256_sub_epi32(_mm256_add_epi32(yr, yr), yodd);

			/* Apply sign bit. */
			yr = _mm256_sub_epi32(_mm256_xor_si256(yr, yneg), yneg);

			yxx = _mm256_blend_epi16(
				_mm256_slli_epi64(yxx, 16), yr, 0x11);
		}

		/* Squared norm support. */
		if (u == n) {
			ysn2 = ysn1;
			ysn1 = _mm256_setzero_si256();
		}
		ysn1 = _mm256_add_epi16(ysn1, _mm256_mullo_epi16(yxx, yxx));

		/* In each 64-bit word, we have four output values, over
		   16 bits each, and in reverse order. We need bytes, and
		   to put them back in the right order. */
		yxx = _mm256_shuffle_epi8(yxx, _mm256_setr_epi8(
			6, 4, 2, 0, 14, 12, 10, 8,
			-1, -1, -1, -1, -1, -1, -1, -1,
			6, 4, 2, 0, 14, 12, 10, 8,
			-1, -1, -1, -1, -1, -1, -1, -1));
		yxx = _mm256_permute4x64_epi64(yxx, 0xD8);
		_mm_storeu_si128((__m128i *)(x + u),
			_mm256_castsi256_si128(yxx));
	}

	/* We have 32 partial sums to add for the square norm. */
	__m256i ymlo = _mm256_set1_epi32(0xFFFF);
	ysn1 = _mm256_add_epi32(
		_mm256_and_si256(ysn1, ymlo),
		_mm256_srli_epi32(ysn1, 16));
	ysn2 = _mm256_add_epi32(
		_mm256_and_si256(ysn2, ymlo),
		_mm256_srli_epi32(ysn2, 16));
	ysn1 = _mm256_add_epi32(ysn1, ysn2);
	ysn1 = _mm256_add_epi32(ysn1, _mm256_srli_epi64(ysn1, 32));
	ysn1 = _mm256_add_epi32(ysn1, _mm256_bsrli_epi128(ysn1, 8));
	return _mm_cvtsi128_si32(_mm_add_epi32(
		_mm256_castsi256_si128(ysn1),
		_mm256_extracti128_si256(ysn1, 1)));

#else // HAWK_AVX2

	uint32_t sn = 0;
	for (size_t j = 0; j < 4; j ++) {
		shake_context sc;
		if (sc_extra != NULL) {
			sc = *sc_extra;
		} else {
			shake_init(&sc, 256);
		}
		seed[40] = (uint8_t)j;
		shake_inject(&sc, seed, 41);
		shake_flip(&sc);
		for (size_t u = 0; u < (n << 1); u += 16) {
			union {
				uint8_t b[40];
				uint16_t w[20];
				uint64_t q[5];
			} buf;
			shake_extract(&sc, buf.b, 40);
			for (size_t k = 0; k < 4; k ++) {
				size_t v = u + (j << 2) + k;
				uint64_t lo = dec64le(buf.b + (k << 3));
				uint32_t hi = dec16le(buf.b + 32 + (k << 1));

				/* Extract sign bit. */
				uint32_t neg = -(uint32_t)(lo >> 63);
				lo &= 0x7FFFFFFFFFFFFFFF;
				hi &= 0x7FFF;

				/* Use even or odd column depending on
				   parity of t. */
				uint32_t pbit = (t[v >> 3] >> (v & 7)) & 1;
				uint64_t p_odd = -(uint64_t)pbit;
				uint32_t p_oddw = (uint32_t)p_odd;

				uint32_t r = 0;
				for (size_t i = 0; i < hi_len; i += 2) {
					uint64_t tlo0 = tab_lo[i + 0];
					uint64_t tlo1 = tab_lo[i + 1];
					uint64_t tlo = tlo0
						^ (p_odd & (tlo0 ^ tlo1));
					uint32_t cc =
						(uint32_t)((lo - tlo) >> 63);
					uint32_t thi0 = tab_hi[i + 0];
					uint32_t thi1 = tab_hi[i + 1];
					uint32_t thi = thi0
						^ (p_oddw & (thi0 ^ thi1));
					r += (hi - thi - cc) >> 31;
				}
				uint32_t hinz = (hi - 1) >> 31;
				for (size_t i = hi_len; i < lo_len; i += 2) {
					uint64_t tlo0 = tab_lo[i + 0];
					uint64_t tlo1 = tab_lo[i + 1];
					uint64_t tlo = tlo0
						^ (p_odd & (tlo0 ^ tlo1));
					uint32_t cc =
						(uint32_t)((lo - tlo) >> 63);
					r += hinz & cc;
				}

				/* Multiply by 2 and apply parity. */
				r = (r << 1) - p_oddw;

				/* Apply sign bit. */
				r = (r ^ neg) - neg;

				x[v] = (int8_t)*(int32_t *)&r;
				sn += r * r;
			}
		}
	}
	return sn;

#endif // HAWK_AVX2
}

/*
 * Alternate function for sampling x; the same mechanism is used, but the
 * provided RNG is used directly instead of instantiating four SHAKE
 * instances in parallel.
 *
 * Returned value is the squared norm of x.
 */
TARGET_AVX2
static uint32_t
sig_gauss_alt(unsigned logn,
	void (*rng)(void *ctx, void *dst, size_t len), void *rng_context,
	int8_t *x, const uint8_t *t)
{
	const uint16_t *tab_hi;
	const uint64_t *tab_lo;
	size_t hi_len, lo_len;

	switch (logn) {
	case 8:
		tab_hi = sig_gauss_hi_Hawk_256;
		tab_lo = sig_gauss_lo_Hawk_256;
		hi_len = SG_MAX_HI_Hawk_256;
		lo_len = SG_MAX_LO_Hawk_256;
		break;
	case 9:
		tab_hi = sig_gauss_hi_Hawk_512;
		tab_lo = sig_gauss_lo_Hawk_512;
		hi_len = SG_MAX_HI_Hawk_512;
		lo_len = SG_MAX_LO_Hawk_512;
		break;
	default: /* 10 */
		tab_hi = sig_gauss_hi_Hawk_1024;
		tab_lo = sig_gauss_lo_Hawk_1024;
		hi_len = SG_MAX_HI_Hawk_1024;
		lo_len = SG_MAX_LO_Hawk_1024;
		break;
	}

	/*
	 * We produce 2*n samples. Each sample requires two elements
	 * from the RNG: a low part (64 bits) and a high part (16 bits).
	 * A SHAKE instance produces 64-bit words in groups of five
	 * (little-endian encoding is assumed); the first four words are
	 * the low parts for four samples (lo0, lo1, lo2 and lo3), and the
	 * fifth word contains the high parts for the four samples
	 * (hi0 + (hi1 << 16) + (hi2 << 32) + (hi3 << 48)).
	 *
	 * We formally use four parallel SHAKE instances, instantiated
	 * over seeds obtained from the source RNG. For j = 0 to 3,
	 * instance j produces samples of index 16*i + 4*j + k, with
	 * k = 0, 1, 2 or 3. A small, RAM-constrained implementation
	 * will use the four instances sequentially, reusing the space
	 * for the SHAKE context; a large system with vector instructions
	 * (e.g. AVX2) might run the four SHAKE instances at the same time.
	 */
	size_t n = (size_t)1 << logn;
#if HAWK_AVX2

	/*
	 * Prepare tables. We want to pre-expand values into AVX2
	 * registers, and also to have fixed-length tables so that the
	 * compiler can unroll loops where appropriate. Fortunately,
	 * the tables for n=512 and n=1024 have the same length (this is
	 * slightly suboptimal for n=256, which has smaller tables).
	 */
	__m256i ytab_hi[10];
	__m256i ytab_lo[26];
	for (size_t i = 0; i < hi_len; i ++) {
		ytab_hi[i] = _mm256_set1_epi64x(tab_hi[i]);
	}
	for (size_t i = hi_len; i < 10; i ++) {
		ytab_hi[i] = _mm256_setzero_si256();
	}
	for (size_t i = 0; i < lo_len; i ++) {
		ytab_lo[i] = _mm256_set1_epi64x(tab_lo[i]);
	}
	for (size_t i = lo_len; i < 26; i ++) {
		ytab_lo[i] = _mm256_setzero_si256();
	}

	__m256i y15 = _mm256_set1_epi64x(0x7FFF);
	__m256i y63 = _mm256_set1_epi64x(0x7FFFFFFFFFFFFFFF);

	/*
	 * Squared norm: we accumulate 16 parallel sums.
	 * Each sum can accumulate up to 128 values (for degree n = 1024,
	 * we sample 2048 values, and 2048/16 = 128) and each value
	 * can be up to 26^2, for a total of 93312, which does not fit
	 * in 16 bits. It is extremely improbable that we ever reach that
	 * value (since extreme values of coefficients of x are very
	 * improbable) but, for completeness, we move the partial sums
	 * at mid-course (when moving from x0 to x1) so that such counters
	 * fit in 16 bits each.
	 */
	__m256i ysn1 = _mm256_setzero_si256();
	__m256i ysn2 = _mm256_setzero_si256();

	/*
	 * Sample values by chunks of 16.
	 */
	for (size_t u = 0; u < (n << 1); u += 16) {
		/*
		 * Get 16*10 bytes from the random source.
		 */
		union {
			__m256i y[5];
			uint8_t b[160];
		} buf;
		rng(rng_context, buf.b, sizeof buf.b);
		__m256i yhi_src = buf.y[4];
		uint64_t tb0 = (uint64_t)t[(u >> 3) + 0] << 31;
		uint64_t tb1 = tb0 >> 4;
		uint64_t tb2 = (uint64_t)t[(u >> 3) + 1] << 31;
		uint64_t tb3 = tb2 >> 4;
		__m256i ypb = _mm256_setr_epi64x(tb0, tb1, tb2, tb3);

		__m256i yxx = _mm256_setzero_si256();
		for (size_t k = 0; k < 4; k ++) {
			__m256i ylo = buf.y[k];
			__m256i yhi = _mm256_and_si256(yhi_src, y15);
			yhi_src = _mm256_srli_epi64(yhi_src, 16);

			/* Extract sign bit. */
			__m256i yneg = _mm256_shuffle_epi32(
				_mm256_srai_epi32(ylo, 31), 0xF5);
			ylo = _mm256_and_si256(ylo, y63);

			/* Use even or odd column depending on
			   parity of t. */
			__m256i yodd = _mm256_shuffle_epi32(
				_mm256_srai_epi32(ypb, 31), 0xA0);
			ypb = _mm256_srli_epi64(ypb, 1);

			__m256i yr = _mm256_setzero_si256();
			for (size_t i = 0; i < 10; i += 2) {
				__m256i ytlo = _mm256_or_si256(
					_mm256_andnot_si256(yodd, ytab_lo[i]),
					_mm256_and_si256(yodd, ytab_lo[i + 1]));
				__m256i ycc = _mm256_srli_epi64(
					_mm256_sub_epi64(ylo, ytlo), 63);
				__m256i ythi = _mm256_or_si256(
					_mm256_andnot_si256(yodd, ytab_hi[i]),
					_mm256_and_si256(yodd, ytab_hi[i + 1]));
				yr = _mm256_add_epi32(yr, _mm256_srli_epi32(
					_mm256_sub_epi32(_mm256_sub_epi32(
						yhi, ythi), ycc), 31));
			}
			__m256i yhinz = _mm256_cmpeq_epi32(
				yhi, _mm256_setzero_si256());
			for (size_t i = 10; i < 26; i += 2) {
				__m256i ytlo = _mm256_or_si256(
					_mm256_andnot_si256(yodd, ytab_lo[i]),
					_mm256_and_si256(yodd, ytab_lo[i + 1]));
				__m256i ycc = _mm256_srli_epi64(
					_mm256_sub_epi64(ylo, ytlo), 63);
				yr = _mm256_add_epi32(yr,
					_mm256_and_si256(yhinz, ycc));
			}

			/* Multiply by 2 and apply parity. */
			yr = _mm256_sub_epi32(_mm256_add_epi32(yr, yr), yodd);

			/* Apply sign bit. */
			yr = _mm256_sub_epi32(_mm256_xor_si256(yr, yneg), yneg);

			yxx = _mm256_blend_epi16(
				_mm256_slli_epi64(yxx, 16), yr, 0x11);
		}

		/* Squared norm support. */
		if (u == n) {
			ysn2 = ysn1;
			ysn1 = _mm256_setzero_si256();
		}
		ysn1 = _mm256_add_epi16(ysn1, _mm256_mullo_epi16(yxx, yxx));

		/* In each 64-bit word, we have four output values, over
		   16 bits each, and in reverse order. We need bytes, and
		   to put them back in the right order. */
		yxx = _mm256_shuffle_epi8(yxx, _mm256_setr_epi8(
			6, 4, 2, 0, 14, 12, 10, 8,
			-1, -1, -1, -1, -1, -1, -1, -1,
			6, 4, 2, 0, 14, 12, 10, 8,
			-1, -1, -1, -1, -1, -1, -1, -1));
		yxx = _mm256_permute4x64_epi64(yxx, 0xD8);
		_mm_storeu_si128((__m128i *)(x + u),
			_mm256_castsi256_si128(yxx));
	}

	/* We have 32 partial sums to add for the square norm. */
	__m256i ymlo = _mm256_set1_epi32(0xFFFF);
	ysn1 = _mm256_add_epi32(
		_mm256_and_si256(ysn1, ymlo),
		_mm256_srli_epi32(ysn1, 16));
	ysn2 = _mm256_add_epi32(
		_mm256_and_si256(ysn2, ymlo),
		_mm256_srli_epi32(ysn2, 16));
	ysn1 = _mm256_add_epi32(ysn1, ysn2);
	ysn1 = _mm256_add_epi32(ysn1, _mm256_srli_epi64(ysn1, 32));
	ysn1 = _mm256_add_epi32(ysn1, _mm256_bsrli_epi128(ysn1, 8));
	return _mm_cvtsi128_si32(_mm_add_epi32(
		_mm256_castsi256_si128(ysn1),
		_mm256_extracti128_si256(ysn1, 1)));

#else // HAWK_AVX2

	uint32_t sn = 0;
	for (size_t u = 0; u < (n << 1); u += 16) {
		union {
			uint8_t b[160];
			uint16_t w[80];
			uint64_t q[20];
		} buf;
		rng(rng_context, buf.b, sizeof buf.b);
		for (size_t j = 0; j < 4; j ++) {
			for (size_t k = 0; k < 4; k ++) {
				size_t v = u + (j << 2) + k;
				uint64_t lo = dec64le(
					buf.b + (j << 3) + (k << 5));
				uint32_t hi = dec16le(
					buf.b + (j << 3) + 128 + (k << 1));

				/* Extract sign bit. */
				uint32_t neg = -(uint32_t)(lo >> 63);
				lo &= 0x7FFFFFFFFFFFFFFF;
				hi &= 0x7FFF;

				/* Use even or odd column depending on
				   parity of t. */
				uint32_t pbit = (t[v >> 3] >> (v & 7)) & 1;
				uint64_t p_odd = -(uint64_t)pbit;
				uint32_t p_oddw = (uint32_t)p_odd;

				uint32_t r = 0;
				for (size_t i = 0; i < hi_len; i += 2) {
					uint64_t tlo0 = tab_lo[i + 0];
					uint64_t tlo1 = tab_lo[i + 1];
					uint64_t tlo = tlo0
						^ (p_odd & (tlo0 ^ tlo1));
					uint32_t cc =
						(uint32_t)((lo - tlo) >> 63);
					uint32_t thi0 = tab_hi[i + 0];
					uint32_t thi1 = tab_hi[i + 1];
					uint32_t thi = thi0
						^ (p_oddw & (thi0 ^ thi1));
					r += (hi - thi - cc) >> 31;
				}
				uint32_t hinz = (hi - 1) >> 31;
				for (size_t i = hi_len; i < lo_len; i += 2) {
					uint64_t tlo0 = tab_lo[i + 0];
					uint64_t tlo1 = tab_lo[i + 1];
					uint64_t tlo = tlo0
						^ (p_odd & (tlo0 ^ tlo1));
					uint32_t cc =
						(uint32_t)((lo - tlo) >> 63);
					r += hinz & cc;
				}

				/* Multiply by 2 and apply parity. */
				r = (r << 1) - p_oddw;

				/* Apply sign bit. */
				r = (r ^ neg) - neg;

				x[v] = (int8_t)*(int32_t *)&r;
				sn += r * r;
			}
		}
	}
	return sn;

#endif // HAWK_AVX2
}

/*
 * Returned value:
 *   1   first non-zero coefficient of s is positive
 *  -1   first non-zero coefficient of s is negative
 *   0   s is entirely zero
 */
TARGET_AVX2
static int32_t
poly_symbreak(unsigned logn, const int16_t *s)
{
	size_t n = (size_t)1 << logn;
#if HAWK_AVX2
	uint32_t rp = 0, rn = 0;
	uint32_t c = 0xFFFFFFFF;
	for (size_t u = 0; u < n; u += 16) {
		__m256i yy = _mm256_loadu_si256((const __m256i *)(s + u));
		__m256i yp = _mm256_cmpgt_epi16(yy, _mm256_setzero_si256());
		__m256i yn = _mm256_cmpgt_epi16(_mm256_setzero_si256(), yy);
		uint32_t mp = _mm256_movemask_epi8(yp);
		uint32_t mn = _mm256_movemask_epi8(yn);
		rp |= c & mp;
		rn |= c & mn;
		uint32_t x = mp | mn;
		c &= ~tbmask(x | -x);
	}
	uint32_t t = rp | rn | 0x80000000;
#if defined _MSC_VER
	unsigned long k;
	(void)_BitScanForward(&k, t);
#else
	unsigned k = _bit_scan_forward(t);
#endif
	return ((rp >> k) & 1) - ((rn >> k) & 1);
#else // HAWK_AVX2
	uint32_t r = 0;
	uint32_t c = 0xFFFFFFFF;
	for (size_t u = 0; u < n; u ++) {
		uint32_t x = (uint32_t)s[u];
		uint32_t nz = c & tbmask(x | -x);
		c &= ~nz;
		r |= nz & (tbmask(x) | 1);
	}
	return r;
#endif // HAWK_AVX2
}

/*
 * Encode the signature, with output length exactly sig_len bytes.
 * Padding is applied if necessary. Returned value is 1 on success, 0
 * on error; an error is reported if the signature does not fit in the
 * provided buffer.
 */
TARGET_AVX2
static int
encode_sig(unsigned logn, void *sig, size_t sig_len,
	const uint8_t *salt, size_t salt_len, const int16_t *s1)
{
	size_t n = (size_t)1 << logn;
	int low = (logn == 10) ? 6 : 5;
	uint8_t *buf = (uint8_t *)sig;
	size_t buf_len = sig_len;

	/* We check the minimal size, including at least n bits for the
	   variable part. */
	if (buf_len < salt_len + ((uint32_t)(low + 2) << (logn - 3))) {
		return 0;
	}

	/* Salt */
	memcpy(buf, salt, salt_len);
	buf += salt_len;
	buf_len -= salt_len;

	/* Sign bits */
#if HAWK_AVX2
	__m256i ys1 = _mm256_setr_epi8(
		1, 3, 5, 7, 9, 11, 13, 15, -1, -1, -1, -1, -1, -1, -1, -1,
		1, 3, 5, 7, 9, 11, 13, 15, -1, -1, -1, -1, -1, -1, -1, -1);
	for (size_t u = 0; u < n; u += 32) {
		__m256i y0 = _mm256_loadu_si256((__m256i *)(s1 + u +  0));
		__m256i y1 = _mm256_loadu_si256((__m256i *)(s1 + u + 16));
		y0 = _mm256_shuffle_epi8(y0, ys1);
		y1 = _mm256_shuffle_epi8(y1, ys1);
		__m256i yy = _mm256_unpacklo_epi64(y0, y1);
		yy = _mm256_permute4x64_epi64(yy, 0xD8);
		*(uint32_t *)(buf + (u >> 3)) = _mm256_movemask_epi8(yy);
	}
#else // HAWK_AVX2
	for (size_t u = 0; u < n; u += 8) {
		unsigned x = 0;
		for (size_t v = 0; v < 8; v ++) {
			x |= (*(const uint16_t *)(s1 + u + v) >> 15) << v;
		}
		buf[u >> 3] = x;
	}
#endif // HAWK_AVX2
	buf += (n >> 3);
	buf_len -= (n >> 3);

	/* Fixed-size parts */
#if HAWK_AVX2
	if (low == 5) {
		/*
		 * 16 values yield 80 bits = 10 bytes.
		 * The variable part has size at least 256 bits (32 bytes)
		 * beyond the fixed-size part, so we can write full 16-byte
		 * chunks.
		 */
		__m256i yp0 = _mm256_setr_epi8(
			0, 2, 4, 6, 8, 10, 12, 14,
			-1, -1, -1, -1, -1, -1, -1, -1,
			0, 2, 4, 6, 8, 10, 12, 14,
			-1, -1, -1, -1, -1, -1, -1, -1);
		__m256i ym1 = _mm256_set1_epi16(0x001F);
		__m256i ym2 = _mm256_set1_epi16(0x1F00);
		__m256i ym3 = _mm256_set1_epi32(0x000003FF);
		__m256i ym4 = _mm256_set1_epi32(0x03FF0000);
		__m256i ym5 = _mm256_set1_epi64x(0x00000000000FFFFF);
		__m256i ym6 = _mm256_set1_epi64x(0x000FFFFF00000000);
		__m128i xp1 = _mm_setr_epi8(
			0, 1, 2, 3, 4, 8, 9, 10, 11, 12,
			-1, -1, -1, -1, -1, -1);

		for (size_t u = 0; u < n; u += 16) {
			__m256i yy = _mm256_loadu_si256((__m256i *)(s1 + u));
			yy = _mm256_xor_si256(yy, _mm256_srai_epi16(yy, 15));
			yy = _mm256_shuffle_epi8(yy, yp0);
			yy = _mm256_or_si256(
				_mm256_and_si256(yy, ym1),
				_mm256_srli_epi16(
					_mm256_and_si256(yy, ym2), 3));
			yy = _mm256_or_si256(
				_mm256_and_si256(yy, ym3),
				_mm256_srli_epi32(
					_mm256_and_si256(yy, ym4), 6));
			yy = _mm256_or_si256(
				_mm256_and_si256(yy, ym5),
				_mm256_srli_epi64(
					_mm256_and_si256(yy, ym6), 12));
			yy = _mm256_permute4x64_epi64(yy, 0xD8);
			__m128i xx = _mm_shuffle_epi8(
				_mm256_castsi256_si128(yy), xp1);
			_mm_storeu_si128((__m128i *)buf, xx);
			buf += 10;
		}
	} else {
		/*
		 * low = 6
		 * 16 values yield 96 bits = 12 bytes.
		 * The variable part has size at least 256 bits (32 bytes)
		 * beyond the fixed-size part, so we can write full 16-byte
		 * chunks.
		 */
		__m256i yp0 = _mm256_setr_epi8(
			0, 2, 4, 6, 8, 10, 12, 14,
			-1, -1, -1, -1, -1, -1, -1, -1,
			0, 2, 4, 6, 8, 10, 12, 14,
			-1, -1, -1, -1, -1, -1, -1, -1);
		__m256i ym1 = _mm256_set1_epi16(0x003F);
		__m256i ym2 = _mm256_set1_epi16(0x3F00);
		__m256i ym3 = _mm256_set1_epi32(0x00000FFF);
		__m256i ym4 = _mm256_set1_epi32(0x0FFF0000);
		__m128i xp1 = _mm_setr_epi8(
			0, 1, 2, 4, 5, 6, 8, 9, 10, 12, 13, 14, -1, -1, -1, -1);
		for (size_t u = 0; u < n; u += 16) {
			__m256i yy = _mm256_loadu_si256((__m256i *)(s1 + u));
			yy = _mm256_xor_si256(yy, _mm256_srai_epi16(yy, 15));
			yy = _mm256_shuffle_epi8(yy, yp0);
			yy = _mm256_or_si256(
				_mm256_and_si256(yy, ym1),
				_mm256_srli_epi16(
					_mm256_and_si256(yy, ym2), 2));
			yy = _mm256_or_si256(
				_mm256_and_si256(yy, ym3),
				_mm256_srli_epi32(
					_mm256_and_si256(yy, ym4), 4));
			yy = _mm256_permute4x64_epi64(yy, 0xD8);
			__m128i xx = _mm_shuffle_epi8(
				_mm256_castsi256_si128(yy), xp1);
			_mm_storeu_si128((__m128i *)buf, xx);
			buf += 12;
		}
	}
#else // HAWK_AVX2
	uint32_t low_mask = ((uint32_t)1 << low) - 1;
	for (size_t u = 0; u < n; u += 8) {
		uint64_t x = 0;
		for (size_t v = 0, vv = 0; v < 8; v ++, vv += low) {
			uint32_t w = (uint32_t)s1[u + v];
			w ^= tbmask(w);
			x |= (uint64_t)(w & low_mask) << vv;
		}
		for (int i = 0; i < (low << 3); i += 8) {
			*buf ++ = (uint8_t)(x >> i);
		}
	}
#endif // HAWK_AVX2
	buf_len -= (size_t)low << (logn - 3);

	/* Variable-size parts */
#if HAWK_AVX2
#if defined __x86_64__ || defined _M_X86
	/*
	 * In 64-bit mode, we can first handle most values by groups of 3
	 * (with at most 7 accumulated bits, 3 values add up to a maximum
	 * of 7 + 3*16 = 55 bits), and write 64-bit words. This avoids
	 * conditional jumps (the cost of writing the same bytes several
	 * times is absorbed by the write buffer; mispredicted conditional
	 * jumps are expensive). We have to stop before the last 64 values
	 * to encode, since these might need fewer than 8 bytes to write.
	 */
	uint64_t accq = 0;
	unsigned accq_off = 0;
	size_t j;
	for (j = 0; j <= (n - 64); j += 3) {
		uint32_t w0 = (uint32_t)s1[j + 0];
		uint32_t w1 = (uint32_t)s1[j + 1];
		uint32_t w2 = (uint32_t)s1[j + 2];
		unsigned k0 = (w0 ^ tbmask(w0)) >> low;
		unsigned k1 = (w1 ^ tbmask(w1)) >> low;
		unsigned k2 = (w2 ^ tbmask(w2)) >> low;
		accq_off += k0;
		accq |= (uint64_t)1 << accq_off;
		accq_off += 1 + k1;
		accq |= (uint64_t)1 << accq_off;
		accq_off += 1 + k2;
		accq |= (uint64_t)1 << accq_off;
		accq_off ++;
		if (buf_len < 8) {
			return 0;
		}
		*(uint64_t *)buf = accq;
		unsigned tt = accq_off & ~0x7u;
		buf += tt >> 3;
		buf_len -= tt >> 3;
		accq >>= tt;
		accq_off -= tt;
	}

	uint32_t acc = (uint32_t)accq;
	int acc_len = (int)accq_off;
#else
	uint32_t acc = 0;
	int acc_len = 0;
	size_t j = 0;
#endif
#else // HAWK_AVX2
	uint32_t acc = 0;
	int acc_len = 0;
	size_t j = 0;
#endif // HAWK_AVX2
	for (size_t u = j; u < n; u ++) {
		uint32_t w = (uint32_t)s1[u];
		int k = (int)((w ^ tbmask(w)) >> low);
		acc |= (uint32_t)1 << (acc_len + k);
		acc_len += 1 + k;
		while (acc_len >= 8) {
			if (buf_len == 0) {
				return 0;
			}
			*buf ++ = (uint8_t)acc;
			buf_len --;
			acc >>= 8;
			acc_len -= 8;
		}
	}
	if (acc_len > 0) {
		if (buf_len == 0) {
			return 0;
		}
		*buf ++ = (uint8_t)acc;
		buf_len --;
	}

	/* Padding. */
	memset(buf, 0, buf_len);
	return 1;
}

/* see hawk.h */
void
hawk_sign_start(shake_context *sc_data)
{
	shake_init(sc_data, 256);
}

TARGET_AVX2
static int
sign_finish_inner(unsigned logn, int use_shake,
	void (*rng)(void *ctx, void *dst, size_t len), void *rng_context,
	void *sig, const shake_context *sc_data,
	const void *priv, size_t priv_len, void *tmp, size_t tmp_len)
{
	/*
	 * Ensure that the tmp[] buffer has proper alignment for 64-bit
	 * access.
	 */
	if (tmp_len < 7) {
		return 0;
	}
	if (logn < 8 || logn > 10) {
		return 0;
	}
	uintptr_t utmp1 = (uintptr_t)tmp;
	uintptr_t utmp2 = (utmp1 + 7) & ~(uintptr_t)7;
	tmp_len -= (size_t)(utmp2 - utmp1);
	uint32_t *tt32 = (uint32_t *)utmp2;
	if (tmp_len < ((size_t)6 << logn)) {
		return 0;
	}

	/*
	 * Check whether the private key is decoded or encoded.
	 */
	int priv_decoded;
	if (priv_len == HAWK_PRIVKEY_SIZE(logn)) {
		priv_decoded = 0;
	} else if (priv_len == HAWK_PRIVKEY_DECODED_SIZE(logn)) {
		priv_decoded = 1;
	} else {
		return 0;
	}

	/*
	 * Hawk parameters from: https://eprint.iacr.org/2022/1155
	 *
	 *   logn                   8         9       10
	 *   salt_len (bits)      112       192      320
	 *   sigma_sign         1.010     1.278    1.299
	 *   sigma_ver          1.042     1.425    1.571
	 *   sigma_sec          1.042     1.425    1.974
	 *   sigma_pk             1.1       1.5      2.0
	 *
	 * Note: sigma_ver is changed to 1.042 for logn=8 and 1.571 for
	 * logn=10 (compared to the eprint).
	 *
	 * Maximum squared norm of x = 2*n*(sigma_ver^2).
	 * max_xnorm is used for the squared norm of 2*x (as returned
	 * by sig_gauss()).
	 */
	size_t n = (size_t)1 << logn;
	size_t salt_len;
	uint32_t max_xnorm;
	switch (logn) {
	case 8:
		salt_len = 14;
		max_xnorm = 2223;
		break;
	case 9:
		salt_len = 24;
		max_xnorm = 8317;
		break;
	case 10:
		salt_len = 40;
		max_xnorm = 20218;
		break;
	default:
		return 0;
	}
	size_t seed_len = 8 + ((size_t)1 << (logn - 5));
	size_t hpub_len = (size_t)1 << (logn - 4);

	/*
	 * Memory layout:
	 *    g    n bytes
	 *    ww   2*n bytes
	 *    x0   n bytes
	 *    x1   n bytes
	 *    f    n bytes
	 *
	 * ww is the area where we will perform mod 2 computations.
	 */
	int8_t *g = (int8_t *)tt32;
	uint8_t *ww = (uint8_t *)(g + n);
	int8_t *x0 = (int8_t *)(ww + 2 * n);
	int8_t *x1 = x0 + n;
	int8_t *f = x1 + n;

	/*
	 * Re-expand the private key.
	 */
	const uint8_t *F2;
	const uint8_t *G2;
	const void *hpub;
	if (priv_decoded) {
		f = (int8_t *)priv;
		g = f + n;
		F2 = (const uint8_t *)(g + n);
		G2 = F2 + (n >> 3);
		hpub = G2 + (n >> 3);
	} else {
		const uint8_t *secbuf = (const uint8_t *)priv;
		Hawk_regen_fg(logn, f, g, secbuf);
		F2 = secbuf + seed_len;
		G2 = F2 + (n >> 3);
		hpub = G2 + (n >> 3);
	}

#if HAWK_DEBUG
	printf("#### Sign (n=%u):\n", 1u << logn);
	print_i8(logn, "f", f);
	print_i8(logn, "g", g);
	print_u1(logn, "F2", F2);
	print_u1(logn, "G2", G2);
	print_blob("hpub", hpub, hpub_len);
#endif

	/*
	 * SHAKE256 computations will use this context structure. We do
	 * not modify the input context value.
	 */
	shake_context scd;

	/*
	 * hm <- SHAKE256(message || hpub)
	 */
	uint8_t hm[64];
	scd = *sc_data;
	shake_inject(&scd, hpub, hpub_len);
	shake_flip(&scd);
	shake_extract(&scd, hm, sizeof hm);

#if HAWK_DEBUG
	printf("# hm = SHAKE256(message || hpub) (64 bytes)\n");
	print_blob("hm", hm, sizeof hm);
#endif

	for (uint32_t attempt = 0;; attempt += 2) {
		/*
		 * We get temporary values (of n/8 bytes each) inside ww.
		 *    t0    n/8 bytes
		 *    t1    n/8 bytes
		 *    h0    n/8 bytes
		 *    h1    n/8 bytes
		 *    f2    n/8 bytes
		 *    g2    n/8 bytes
		 *    xx    10*n/8 bytes
		 */
		uint8_t *t0 = ww;
		uint8_t *t1 = t0 + (n >> 3);
		uint8_t *h0 = t1 + (n >> 3);
		uint8_t *h1 = h0 + (n >> 3);
		uint8_t *f2 = h1 + (n >> 3);
		uint8_t *g2 = f2 + (n >> 3);
		uint8_t *xx = g2 + (n >> 3);

		/*
		 * Generate the salt.
		 *
		 * In normal mode (with SHAKE-based sampling), we use
		 * SHAKE256(hm || kgseed || counter || rand), i.e. the
		 * concatenation of the message, the private key seed, an
		 * attempt counter, and some extra randomness (from the
		 * provided RNG); this ensures security even if the RNG
		 * does not provide good randomness. If (f,g) were provided
		 * already decoded, we use f and g directly instead of
		 * kgseed.
		 *
		 * In alternate mode, as per the API, we use the RNG directly.
		 */
		uint8_t salt[40];
		rng(rng_context, salt, salt_len);
		if (use_shake) {
			uint8_t tbuf[4];
			enc32le(tbuf, attempt);
			shake_init(&scd, 256);
			shake_inject(&scd, hm, sizeof hm);
			if (priv_decoded) {
				shake_inject(&scd, priv, n << 1);
			} else {
				shake_inject(&scd, priv, seed_len);
			}
			shake_inject(&scd, tbuf, sizeof tbuf);
			shake_inject(&scd, salt, salt_len);
			shake_flip(&scd);
			shake_extract(&scd, salt, salt_len);
		}

#if HAWK_DEBUG
		print_blob("salt", salt, salt_len);
#endif

		/*
		 * h <- SHAKE256(hm || salt)  (out: 2*n bits)
		 */
		shake_init(&scd, 256);
		shake_inject(&scd, hm, sizeof hm);
		shake_inject(&scd, salt, salt_len);
		shake_flip(&scd);
		shake_extract(&scd, h0, n >> 2);

#if HAWK_DEBUG
		printf("# h = SHAKE256(hm || salt) (2*n bits)\n");
		print_u1(logn, "h0", h0);
		print_u1(logn, "h1", h1);
#endif

		/*
		 * t <- B*h  (mod 2)
		 */
		extract_lowbit(logn, f2, f);
		extract_lowbit(logn, g2, g);
		basis_m2_mul(logn, t0, t1, h0, h1, f2, g2, F2, G2, xx);

#if HAWK_DEBUG
		printf("# t = B*h (mod 2)\n");
		print_u1(logn, "t0", t0);
		print_u1(logn, "t1", t1);
#endif

		/*
		 * x <- D_{t/2}(sigma_sign)
		 * Reject if the squared norm of x is larger than
		 * 2*n*(sigma_ver^2) (this is quite improbable).
		 *
		 * When using SHAKE for the sampling, we also inject
		 * the message, the private key (seed) and the attempt
		 * counter into the SHAKE instances, so that security is
		 * maintained even if the RNG source is poor.
		 */
		uint32_t xsn;
		if (use_shake) {
			uint8_t tbuf[4];
			enc32le(tbuf, attempt + 1);
			shake_init(&scd, 256);
			shake_inject(&scd, hm, sizeof hm);
			if (priv_decoded) {
				shake_inject(&scd, priv, n << 1);
			} else {
				shake_inject(&scd, priv, seed_len);
			}
			shake_inject(&scd, tbuf, sizeof tbuf);
			xsn = sig_gauss(logn, rng, rng_context, &scd, x0, t0);
		} else {
			xsn = sig_gauss_alt(logn, rng, rng_context, x0, t0);
		}
#if HAWK_DEBUG
		printf("# (dx0, dx1) = (2*x0, 2*x1)\n");
		print_i8(logn, "dx0", x0);
		print_i8(logn, "dx1", x1);
		printf("l2norm(2*x)^2 = %lu\n", (unsigned long)xsn);
#endif
		if (xsn > max_xnorm) {
			continue;
		}

		/*
		 * (x0*adj(f) + x1*adj(g))/(f*adj(f) + g*adj(g)) should
		 * have all its coefficients in [-1/2, +1/2]. For
		 * degrees n=512 and n=1024, the key has been generated
		 * so that it is extremely improbable (less than
		 * 2^(-105) and 2^(-315), respectively) that this
		 * property is not met, and we can omit the test (the
		 * risk of miscomputation through a stray cosmic ray is
		 * many orders of magnitude higher).
		 *
		 * For degree n=256, the property may be false with
		 * probability about 2^(-39.5), though the actual
		 * verification failure rate may be lower. Since n=256
		 * is a "challenge" variant, we can tolerate that
		 * failure rate.
		 */

		/*
		 * s1 = (1/2)*h1 + g*x0 - f*x1
		 * We compute 2*(f*x1 - g*x0) = h1 - 2*s1
		 * (we already have 2*x in (x0,x1)).
		 *
		 * We no longer need the mod 2 values, except h1, which we
		 * move to a stack buffer (it has size at most 128 bytes,
		 * we can afford to put it on the stack).
		 *
		 * Memory layout:
		 *    g    n bytes   w1
		 *    --   n bytes   w1
		 *    --   n bytes   w2
		 *    x0   n bytes   w2
		 *    x1   n bytes   w3
		 *    f    n bytes   w3
		 */
		uint8_t h1buf[128];
		memcpy(h1buf, h1, n >> 3);

		/* w1 <- 2*g*x0 (NTT) */
		uint16_t *w1 = (uint16_t *)tt32;
		uint16_t *w2 = w1 + n;
		uint16_t *w3 = w2 + n;
		if (priv_decoded) {
			mq18433_poly_set_small(logn, w1, g);
		} else {
			mq18433_poly_set_small_inplace_low(logn, w1);
		}
		mq18433_poly_set_small_inplace_high(logn, w2);
		mq18433_NTT(logn, w1);
		mq18433_NTT(logn, w2);
#if HAWK_AVX2
		for (size_t u = 0; u < n; u += 16) {
			__m256i y1 = _mm256_loadu_si256((__m256i *)&w1[u]);
			__m256i y2 = _mm256_loadu_si256((__m256i *)&w2[u]);
			y1 = mq18433_montymul_x16(y1, y2);
			_mm256_storeu_si256((__m256i *)&w1[u], y1);
		}
#else // HAWK_AVX2
		for (size_t u = 0; u < n; u ++) {
			w1[u] = mq18433_montymul(w1[u], w2[u]);
		}
#endif // HAWK_AVX2

		/* w3 <- 2*(f*x1 - g*x0) = h1 - 2*s1 */
		mq18433_poly_set_small(logn, w2, x1);
		if (priv_decoded) {
			mq18433_poly_set_small(logn, w3, f);
		} else {
			mq18433_poly_set_small_inplace_high(logn, w3);
		}
		mq18433_NTT(logn, w2);
		mq18433_NTT(logn, w3);
#if HAWK_AVX2
		for (size_t u = 0; u < n; u += 16) {
			__m256i y1 = _mm256_loadu_si256((__m256i *)&w1[u]);
			__m256i y2 = _mm256_loadu_si256((__m256i *)&w2[u]);
			__m256i y3 = _mm256_loadu_si256((__m256i *)&w3[u]);
			y3 = mq18433_tomonty_x16(mq18433_sub_x16(
				mq18433_montymul_x16(y2, y3), y1));
			_mm256_storeu_si256((__m256i *)&w3[u], y3);
		}
#else // HAWK_AVX2
		for (size_t u = 0; u < n; u ++) {
			w3[u] = mq18433_tomonty(mq18433_sub(
				mq18433_montymul(w2[u], w3[u]), w1[u]));
		}
#endif // HAWK_AVX2
		mq18433_iNTT(logn, w3);
		mq18433_poly_snorm(logn, w3);

#if HAWK_DEBUG
		printf("# w = h1 - 2*s1\n");
		print_i16(logn, "w", (int16_t *)w3);
#endif

		/*
		 * sym-break(): if h1 - 2*s1 (currently in w3) is
		 * positive, then we return s1 = (h1 - w3)/2. Otherwise,
		 * we return s1 = h1 - (h1 - w3)/2 = (h1 + w3)/2.
		 * Thus, this uses a conditional negation of w3. We
		 * set nm = -1 if the negation must happen, 0 otherwise.
		 *
		 * We also enforce a limit on the individual elements of s1.
		 */
		int16_t *s1 = (int16_t *)w3;
		uint32_t ps = poly_symbreak(logn, s1);
#if HAWK_DEBUG
		printf("symbreak = %d\n", (int)ps);
#endif
		int lim = 1 << ((logn == 10) ? 10 : 9);
#if HAWK_AVX2
		__m256i ynm = _mm256_set1_epi16(-*(int32_t *)&ps);
		__m256i yplim = _mm256_set1_epi16(lim);
		__m256i ynlim = _mm256_set1_epi16(-lim - 1);
		__m256i ysh0 = _mm256_setr_epi32(0, 2, 4, 6, 8, 10, 12, 14);
		__m256i ysh1 = _mm256_setr_epi32(1, 3, 5, 7, 9, 11, 13, 15);
		__m256i y1 = _mm256_set1_epi16(1);
		__m256i ygg = _mm256_set1_epi16(-1);
		for (size_t u = 0; u < n; u += 16) {
			__m256i yz = _mm256_loadu_si256(
				(const __m256i *)(s1 + u));
			yz = _mm256_sign_epi16(yz, ynm);
			__m256i yh = _mm256_set1_epi32(
				h1buf[u >> 3] | (h1buf[(u >> 3) + 1] << 8));
			__m256i yh0 = _mm256_srlv_epi32(yh, ysh0);
			__m256i yh1 = _mm256_srlv_epi32(yh, ysh1);
			yh = _mm256_blend_epi16(
				yh0, _mm256_slli_epi32(yh1, 16), 0xAA);
			yh = _mm256_and_si256(yh, y1);
			yz = _mm256_srai_epi16(_mm256_add_epi16(yz, yh), 1);
			ygg = _mm256_and_si256(ygg,
				_mm256_and_si256(
					_mm256_cmpgt_epi16(yplim, yz),
					_mm256_cmpgt_epi16(yz, ynlim)));
			_mm256_storeu_si256((__m256i *)(s1 + u), yz);
		}
		if (_mm256_movemask_epi8(ygg) != -1) {
			if (!priv_decoded) {
				Hawk_regen_fg(logn, f, g, priv);
			}
			continue;
		}
#else // HAWK_AVX2
		uint32_t nm = ~tbmask(ps - 1);
		for (size_t u = 0; u < n; u ++) {
			uint32_t z = (uint32_t)s1[u];
			z = ((z ^ nm) - nm) + ((h1buf[u >> 3] >> (u & 7)) & 1);
			int32_t y = *(int32_t *)&z >> 1;
			if (y < -lim || y >= lim) {
				lim = 0;
				break;
			}
			s1[u] = y;
		}
		if (lim == 0) {
#if HAWK_DEBUG
			printf("# limit on s1 exceeded, restarting\n");
#endif
			if (!priv_decoded) {
				Hawk_regen_fg(logn, f, g, priv);
			}
			continue;
		}
#endif // HAWK_AVX2

#if HAWK_DEBUG
		print_i16(logn, "s1", (int16_t *)s1);
#endif

		/*
		 * We have the signature (in s1). We encode it into
		 * the temporary buffer, and (optionally) into the provided
		 * output buffer.
		 */
		size_t sig_len = HAWK_SIG_SIZE(logn);
		if (encode_sig(logn, tmp, sig_len, salt, salt_len, s1)) {
#if HAWK_DEBUG
			print_blob("sig", tmp, sig_len);
#endif
			if (sig != NULL) {
				memcpy(sig, tmp, sig_len);
			}
			return 1;
		}
#if HAWK_DEBUG
		printf("# signature too large, restarting");
#endif
		if (!priv_decoded) {
			Hawk_regen_fg(logn, f, g, priv);
		}
	}
}

/* see hawk.h */
int
hawk_sign_finish(unsigned logn,
	void (*rng)(void *ctx, void *dst, size_t len), void *rng_context,
	void *sig, const shake_context *sc_data,
	const void *priv, void *tmp, size_t tmp_len)
{
	return sign_finish_inner(logn, 1, rng, rng_context, sig, sc_data,
		priv, HAWK_PRIVKEY_SIZE(logn), tmp, tmp_len);
}

/* see hawk.h */
int
hawk_sign_finish_alt(unsigned logn,
	void (*rng)(void *ctx, void *dst, size_t len), void *rng_context,
	void *sig, const shake_context *sc_data,
	const void *priv, size_t priv_len, void *tmp, size_t tmp_len)
{
	return sign_finish_inner(logn, 0, rng, rng_context, sig, sc_data,
		priv, priv_len, tmp, tmp_len);
}

/* see hawk.h */
void
hawk_decode_private_key(unsigned logn, void *priv_dec, const void *priv)
{
	size_t n = (size_t)1 << logn;
	int8_t *f = (int8_t *)priv_dec;
	int8_t *g = f + n;
	size_t seed_len = 8 + ((size_t)1 << (logn - 5));
	size_t hpub_len = (size_t)1 << (logn - 4);
	uint8_t seed[40];
	memcpy(seed, priv, seed_len);
	memmove(g + n, (const uint8_t *)priv + seed_len, (n >> 2) + hpub_len);
	Hawk_regen_fg(logn, f, g, seed);
}
