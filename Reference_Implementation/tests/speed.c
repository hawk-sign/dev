/*
 * Speed benchmark code for Hawk implementation.
 *
 * ==========================(LICENSE BEGIN)============================
 *
 * Copyright (c) 2022 Hawk Project
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
 * IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
 * CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
 * TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
 * SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 *
 * ===========================(LICENSE END)=============================
 *
 * @author   Ludo Pulles <ludo.pulles@cwi.nl>
 *
 * ==========================(LICENSE BEGIN)============================
 *
 * Copyright (c) 2017-2019  Falcon Project
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
 * IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
 * CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
 * TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
 * SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 *
 * ===========================(LICENSE END)=============================
 *
 * @author   Thomas Pornin <thomas.pornin@nccgroup.com>
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/*
 * This code uses only the external API.
 */

#include "../hawk.h"

static void *
xmalloc(size_t len)
{
	void *buf;

	if (len == 0) {
		return NULL;
	}
	buf = malloc(len);
	if (buf == NULL) {
		fprintf(stderr, "memory allocation error\n");
		exit(EXIT_FAILURE);
	}
	return buf;
}

static void
xfree(void *buf)
{
	if (buf != NULL) {
		free(buf);
	}
}

/*
 * Benchmark function takes an opaque context and an iteration count;
 * it returns 0 on success, a negative error code on error.
 */
typedef int (*bench_fun)(void *ctx, unsigned long num);

/*
 * Returned value is the time per iteration in nanoseconds. If the
 * benchmark function reports an error, 0.0 is returned.
 */
static double
do_bench(bench_fun bf, void *ctx, double threshold)
{
	unsigned long num;
	int r;

	/*
	 * Always do a few blank runs to "train" the caches and branch
	 * prediction.
	 */
	r = bf(ctx, 5);
	if (r != 0) {
		fprintf(stderr, "ERR: %d\n", r);
		return 0.0;
	}

	num = 1;
	for (;;) {
		clock_t begin, end;
		double tt;

		begin = clock();
		r = bf(ctx, num);
		end = clock();
		if (r != 0) {
			fprintf(stderr, "ERR: %d\n", r);
			return 0.0;
		}
		tt = (double)(end - begin) / (double)CLOCKS_PER_SEC;
		if (tt >= threshold) {
			return tt * 1000000000.0 / (double)num;
		}

		/*
		 * If the function ran for less than 0.1 seconds then
		 * we simply double the iteration number; otherwise, we
		 * use the run time to try to get a "correct" number of
		 * iterations quickly.
		 */
		if (tt < 0.1) {
			num <<= 1;
		} else {
			unsigned long num2;

			num2 = (unsigned long)((double)num
				* (threshold * 1.1) / tt);
			if (num2 <= num) {
				num2 = num + 1;
			}
			num = num2;
		}
	}
}

typedef struct {
	unsigned logn;
	shake_context rng;
	uint8_t *tmp, *pub, *priv, *priv_dec, *sig;
	void **zpub;
	void **zsig;
} bench_context;

#define CC(x)   do { \
		if (!(x)) { \
			return -1; \
		} \
	} while (0)

static int
bench_keygen(void *ctx, unsigned long num)
{
	bench_context *bc = ctx;
	unsigned logn = bc->logn;
	size_t tmp_len = HAWK_TMPSIZE_KEYGEN(logn);
	while (num -- > 0) {
		CC(hawk_keygen(logn, bc->priv, bc->pub,
			(hawk_rng)&shake_extract, &bc->rng,
			bc->tmp, tmp_len));
	}
	return 0;
}

static int
bench_sign(void *ctx, unsigned long num)
{
	bench_context *bc = ctx;
	unsigned logn = bc->logn;
	size_t tmp_len = HAWK_TMPSIZE_SIGN(logn);
	while (num -- > 0) {
		shake_context scd;
		hawk_sign_start(&scd);
		shake_inject(&scd, "data", 4);
		CC(hawk_sign_finish(logn,
			(hawk_rng)&shake_extract, &bc->rng,
			bc->sig, &scd, bc->priv, bc->tmp, tmp_len));
	}
	return 0;
}

/*
 * "Fast" RNG. On 64-bit x86 systems, we assume that the AES hardware
 * instructions are supported, and we use AES-128 in counter mode
 * (though with subkeys generated directly from SHAKE, not using the
 * normal AES key schedule). On other archs, we use a custom ChaCha8
 * variant.
 */
#if defined __x86_64__ || defined _M_X64
#include <immintrin.h>

typedef struct {
	__m128i sk[11];
	__m128i cc[4];
} fastrng_ctx;

static void
fastrng_init(fastrng_ctx *ac, shake_context *rng)
{
	shake_extract(rng, (void *)ac->sk, sizeof ac->sk);
	ac->cc[0] = _mm_setr_epi32(0, 0, 0, 0);
	ac->cc[1] = _mm_setr_epi32(1, 0, 0, 0);
	ac->cc[2] = _mm_setr_epi32(2, 0, 0, 0);
	ac->cc[3] = _mm_setr_epi32(3, 0, 0, 0);
}

#if defined __GNUC__ || defined __clang__
__attribute__((target("sse2,aes")))
#endif
static void
fastrng(void *context, void *out, size_t len)
{
	fastrng_ctx *ac = context;
	__m128i cc0 = ac->cc[0];
	__m128i cc1 = ac->cc[1];
	__m128i cc2 = ac->cc[2];
	__m128i cc3 = ac->cc[3];
	__m128i xcc = _mm_setr_epi32(4, 0, 0, 0);
	uint8_t *buf = out;
	while (len > 0) {
		__m128i x0 = _mm_xor_si128(cc0, ac->sk[0]);
		__m128i x1 = _mm_xor_si128(cc1, ac->sk[0]);
		__m128i x2 = _mm_xor_si128(cc2, ac->sk[0]);
		__m128i x3 = _mm_xor_si128(cc3, ac->sk[0]);
		cc0 = _mm_add_epi64(cc0, xcc);
		cc1 = _mm_add_epi64(cc1, xcc);
		cc2 = _mm_add_epi64(cc2, xcc);
		cc3 = _mm_add_epi64(cc3, xcc);
		for (int i = 1; i < 10; i ++) {
			x0 = _mm_aesenc_si128(x0, ac->sk[i]);
			x1 = _mm_aesenc_si128(x1, ac->sk[i]);
			x2 = _mm_aesenc_si128(x2, ac->sk[i]);
			x3 = _mm_aesenc_si128(x3, ac->sk[i]);
		}
		x0 = _mm_aesenclast_si128(x0, ac->sk[10]);
		x1 = _mm_aesenclast_si128(x1, ac->sk[10]);
		x2 = _mm_aesenclast_si128(x2, ac->sk[10]);
		x3 = _mm_aesenclast_si128(x3, ac->sk[10]);
		if (len >= 64) {
			_mm_storeu_si128((__m128i *)buf + 0, x0);
			_mm_storeu_si128((__m128i *)buf + 1, x1);
			_mm_storeu_si128((__m128i *)buf + 2, x2);
			_mm_storeu_si128((__m128i *)buf + 3, x3);
			buf += 64;
			len -= 64;
		} else {
			uint8_t tmp[64];
			_mm_storeu_si128((__m128i *)tmp + 0, x0);
			_mm_storeu_si128((__m128i *)tmp + 1, x1);
			_mm_storeu_si128((__m128i *)tmp + 2, x2);
			_mm_storeu_si128((__m128i *)tmp + 3, x3);
			memcpy(buf, tmp, len);
			break;
		}
	}
	ac->cc[0] = cc0;
	ac->cc[1] = cc1;
	ac->cc[2] = cc2;
	ac->cc[3] = cc3;
}

#else

static inline uint32_t
dec32le(const void *src)
{
	const uint8_t *buf = src;
	return (uint32_t)buf[0]
		| ((uint32_t)buf[1] << 8)
		| ((uint32_t)buf[2] << 16)
		| ((uint32_t)buf[3] << 24);
}

static inline void
enc32le(void *dst, uint32_t x)
{
	uint8_t *buf = dst;
	buf[0] = (uint8_t)x;
	buf[1] = (uint8_t)(x >> 8);
	buf[2] = (uint8_t)(x >> 16);
	buf[3] = (uint8_t)(x >> 24);
}

typedef union {
	uint8_t b[40];
	uint32_t d[10];
	uint64_t q[5];
} fastrng_ctx;

static void
fastrng_init(fastrng_ctx *ac, shake_context *rng)
{
	uint8_t tmp[32];
	shake_extract(rng, tmp, sizeof tmp);
	for (size_t u = 0; u < 8; u ++) {
		ac->d[u] = dec32le(tmp + (u << 2));
	}
	ac->q[4] = 0;
}

static void
fastrng(void *context, void *out, size_t len)
{
	/* First constant voluntarily differs from RFC 8439. */
	static const uint32_t CW[] = {
		0xA7C083FE, 0x3320646E, 0x79622d32, 0x6B206574
	};

	fastrng_ctx *ac = context;
	uint8_t *buf = out;
	uint64_t cc = ac->q[4];
	while (len > 0) {
		uint32_t state[16];
		memcpy(&state[0], CW, sizeof CW);
		memcpy(&state[4], ac->d, 32);
		state[12] = (uint32_t)cc;
		state[13] = (uint32_t)(cc >> 32);
		state[14] = 0;
		state[15] = 0;

		/*
		 * Only 8 rounds; ChaCha8() ought to be secure enough:
		 *    https://eprint.iacr.org/2019/1492
		 */
		for (int i = 0; i < 4; i ++) {
#define QROUND(a, b, c, d)   do { \
		state[a] += state[b]; \
		state[d] ^= state[a]; \
		state[d] = (state[d] << 16) | (state[d] >> 16); \
		state[c] += state[d]; \
		state[b] ^= state[c]; \
		state[b] = (state[b] << 12) | (state[b] >> 20); \
		state[a] += state[b]; \
		state[d] ^= state[a]; \
		state[d] = (state[d] <<  8) | (state[d] >> 24); \
		state[c] += state[d]; \
		state[b] ^= state[c]; \
		state[b] = (state[b] <<  7) | (state[b] >> 25); \
        } while (0)

			QROUND( 0,  4,  8, 12);
			QROUND( 1,  5,  9, 13);
			QROUND( 2,  6, 10, 14);
			QROUND( 3,  7, 11, 15);
			QROUND( 0,  5, 10, 15);
			QROUND( 1,  6, 11, 12);
			QROUND( 2,  7,  8, 13);
			QROUND( 3,  4,  9, 14);

#undef QROUND
		}

		for (size_t v = 0; v < 4; v ++) {
			state[v] += CW[v];
		}
		for (size_t v = 4; v < 12; v ++) {
			state[v] += ac->d[v - 4];
		}
		state[12] += (uint32_t)cc;
		state[13] += (uint32_t)(cc >> 32);
		cc ++;

		if (len >= 64) {
			for (size_t v = 0; v < 16; v ++) {
				enc32le(buf + (v << 2), state[v]);
			}
			buf += 64;
			len -= 64;
		} else {
			size_t v;
			for (v = 0; len >= 4; v ++, buf += 4, len -= 4) {
				enc32le(buf, state[v]);
			}
			uint32_t x = state[v];
			while (len -- > 0) {
				*buf ++ = (uint8_t)x;
				x >>= 8;
			}
			break;
		}
	}

	ac->q[4] = cc;
}

#endif

static int
bench_sign_noshake(void *ctx, unsigned long num)
{
	bench_context *bc = ctx;
	unsigned logn = bc->logn;
	size_t priv_dec_len = HAWK_PRIVKEY_DECODED_SIZE(logn);
	hawk_decode_private_key(logn, bc->priv_dec, bc->priv);
	size_t tmp_len = HAWK_TMPSIZE_SIGN(logn);
	fastrng_ctx ac;
	fastrng_init(&ac, &bc->rng);
	while (num -- > 0) {
		shake_context scd;
		hawk_sign_start(&scd);
		shake_inject(&scd, "data", 4);
		CC(hawk_sign_finish_alt(logn,
			&fastrng, &ac,
			bc->sig, &scd, bc->priv_dec, priv_dec_len,
			bc->tmp, tmp_len));
	}
	return 0;
}

static int
bench_verify(void *ctx, unsigned long num)
{
	bench_context *bc = ctx;
	int i = 0;
	int k = 0;
	unsigned logn = bc->logn;
	size_t pub_len = HAWK_PUBKEY_SIZE(logn);
	size_t sig_len = HAWK_SIG_SIZE(logn);
	size_t tmp_len = HAWK_TMPSIZE_VERIFY(logn);
	while (num -- > 0) {
		shake_context scd;
		hawk_verify_start(&scd);
		shake_inject(&scd, "data", 4);
		CC(hawk_verify_finish(logn,
			bc->zsig[k], sig_len, &scd,
			bc->zpub[i], pub_len, bc->tmp, tmp_len));
		if (++ i == 100) {
			i = 0;
		}
		if (++ k == 1000) {
			k = 0;
		}
	}
	return 0;
}

static int
bench_verify_fast(void *ctx, unsigned long num)
{
	bench_context *bc = ctx;
	int i = 0;
	int k = 0;
	unsigned logn = bc->logn;
	size_t pub_len = HAWK_PUBKEY_SIZE(logn);
	size_t sig_len = HAWK_SIG_SIZE(logn);
	size_t tmp_len = HAWK_TMPSIZE_VERIFY_FAST(logn);
	while (num -- > 0) {
		shake_context scd;
		hawk_verify_start(&scd);
		shake_inject(&scd, "data", 4);
		CC(hawk_verify_finish(logn,
			bc->zsig[k], sig_len, &scd,
			bc->zpub[i], pub_len, bc->tmp, tmp_len));
		if (++ i == 100) {
			i = 0;
		}
		if (++ k == 1000) {
			k = 0;
		}
	}
	return 0;
}

static void
test_speed_hawk(unsigned logn, double threshold)
{
	bench_context bc;

	printf("%4u:", 1u << logn);
	fflush(stdout);

	bc.logn = logn;

	/* This is just for tests: we can initialize the RNG with the
	   current time, because security does not matter for tests. */
	uint64_t tq = (uint64_t)time(NULL);
	shake_init(&bc.rng, 256);
	shake_inject(&bc.rng, &tq, sizeof tq);
	shake_flip(&bc.rng);

	size_t priv_len = HAWK_PRIVKEY_SIZE(logn);
	bc.priv = xmalloc(priv_len);
	size_t priv_dec_len = HAWK_PRIVKEY_DECODED_SIZE(logn);
	bc.priv_dec = xmalloc(priv_dec_len);
	size_t pub_len = HAWK_PUBKEY_SIZE(logn);
	bc.pub = xmalloc(pub_len);
	size_t sig_len = HAWK_SIG_SIZE(logn);
	bc.sig = xmalloc(sig_len);
	size_t tmp_len = HAWK_TMPSIZE_KEYGEN(logn);
	bc.tmp = xmalloc(tmp_len);
	printf(" %8.2f", do_bench(&bench_keygen, &bc, threshold) / 1000000.0);
	fflush(stdout);

	/* sign */
	printf(" %8.2f",
		do_bench(&bench_sign, &bc, threshold) / 1000.0);
	fflush(stdout);

	/* sign without SHAKE */
	printf(" %8.2f",
		do_bench(&bench_sign_noshake, &bc, threshold) / 1000.0);
	fflush(stdout);

	bc.zpub = xmalloc(100 * sizeof *bc.zpub);
	bc.zsig = xmalloc(1000 * sizeof *bc.zsig);
	void *zpriv = xmalloc(priv_len);
	for (int i = 0; i < 100; i ++) {
		bc.zpub[i] = xmalloc(pub_len);
		if (!hawk_keygen(logn, zpriv, bc.zpub[i],
			(hawk_rng)&shake_extract, &bc.rng, bc.tmp, tmp_len))
		{
			fprintf(stderr, "ERR keygen\n");
			exit(EXIT_FAILURE);
		}
		for (int j = 0; j < 10; j ++) {
			int k = 100 * j + i;
			bc.zsig[k] = xmalloc(sig_len);
			shake_context scd;
			hawk_sign_start(&scd);
			shake_inject(&scd, "data", 4);
			if (!hawk_sign_finish(logn,
				(hawk_rng)&shake_extract, &bc.rng,
				bc.zsig[k], &scd, zpriv, bc.tmp, tmp_len))
			{
				fprintf(stderr, "ERR sign\n");
				exit(EXIT_FAILURE);
			}
		}
	}
	xfree(zpriv);

	/* verify (normal) */
	printf(" %8.2f", do_bench(&bench_verify, &bc, threshold) / 1000.0);
	fflush(stdout);

	/* verify (fast) */
	printf(" %8.2f", do_bench(&bench_verify_fast, &bc, threshold) / 1000.0);
	fflush(stdout);

	printf("\n");
	fflush(stdout);

	xfree(bc.pub);
	xfree(bc.priv);
	xfree(bc.priv_dec);
	xfree(bc.sig);
	xfree(bc.tmp);

	for (int i = 0; i < 100; i ++) {
		xfree(bc.zpub[i]);
	}
	xfree(bc.zpub);
	for (int k = 0; k < 1000; k ++) {
		xfree(bc.zsig[k]);
	}
	xfree(bc.zsig);
}

int
main(int argc, char *argv[])
{
	double threshold;

	if (argc < 2) {
		threshold = 2.0;
	} else if (argc == 2) {
		threshold = atof(argv[1]);
	} else {
		threshold = -1.0;
	}
	if (threshold <= 0.0 || threshold > 60.0) {
		fprintf(stderr,
"usage: speed [ threshold ]\n"
"'threshold' is the minimum time for a bench run, in seconds (must be\n"
"positive and less than 60).\n");
		exit(EXIT_FAILURE);
	}
	printf("time threshold = %.4f s\n", threshold);
	printf("kg = keygen, sd = sign, sf = sign SHAKE-less, vv = verify, vf = fast verify\n");
	printf("keygen in milliseconds, other values in microseconds\n");
	printf("\n");
	printf("degree  kg(ms)   sd(us)   sf(us)   vv(us)   vf(us)\n");
	fflush(stdout);

	for (unsigned logn = 8; logn <= 10; logn++) {
		test_speed_hawk(logn, threshold);
	}

	return 0;
}
