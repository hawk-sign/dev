#include "hawk_inner.h"

/*
 * Reduce f modulo 2; output is a sequence of n bits (n/8 bytes).
 */
TARGET_AVX2
static void
extract_lowbit(unsigned logn, uint8_t *restrict f2, const int8_t *restrict f)
{
	size_t n = (size_t)1 << logn;
#if HAWK_AVX2
	for (size_t u = 0; u < n; u += 32) {
		__m256i x = _mm256_loadu_si256((const __m256i *)(f + u));
		x = _mm256_slli_epi16(x, 7);
		*(uint32_t *)(f2 + (u >> 3)) = _mm256_movemask_epi8(x);
	}
#else // HAWK_AVX2
	const uint8_t *fu = (const uint8_t *)f;
	for (size_t u = 0; u < n; u += 8) {
		f2[u >> 3] = (fu[u + 0] & 1u)
			| ((fu[u + 1] & 1u) << 1)
			| ((fu[u + 2] & 1u) << 2)
			| ((fu[u + 3] & 1u) << 3)
			| ((fu[u + 4] & 1u) << 4)
			| ((fu[u + 5] & 1u) << 5)
			| ((fu[u + 6] & 1u) << 6)
			| ((fu[u + 7] & 1u) << 7);
	}
#endif // HAWK_AVX2
}

/*
 * Encode the private key.
 */
static size_t
encode_private(unsigned logn, void *restrict dst,
	const void *seed, const int8_t *restrict F, const int8_t *restrict G,
	const void *pub, size_t pub_len)
{
	size_t n = (size_t)1 << logn;
	uint8_t *buf = (uint8_t *)dst;

	/*
	 * Seed.
	 */
	size_t seed_len = 8 + ((size_t)1 << (logn - 5));
	memcpy(buf, seed, seed_len);
	buf += seed_len;

	/*
	 * F mod 2 and G mod 2.
	 */
	extract_lowbit(logn, buf, F);
	buf += (n >> 3);
	extract_lowbit(logn, buf, G);
	buf += (n >> 3);

	/*
	 * Public key hash (SHAKE256; output length is {128, 256, 512} bits
	 * depending on degree).
	 */
	size_t hpub_len = (size_t)1 << (logn - 4);
	shake_context sc;
	shake_init(&sc, 256);
	shake_inject(&sc, pub, pub_len);
	shake_flip(&sc);
	shake_extract(&sc, buf, hpub_len);
	buf += hpub_len;

	return (size_t)(buf - (uint8_t *)dst);
}

/*
 * Width of the fixed-sized part of the encoding of a coefficient of q00
 * or q01 (excluding the sign bit).
 */
static const int8_t low_bits_q00[11] = {
	0, 0, 0, 0, 0, 0, 0, 0,  5,  5,  6
};
static const int8_t low_bits_q01[11] = {
	0, 0, 0, 0, 0, 0, 0, 0,  8,  9, 10
};

/*
 * Golomb-Rice encoding, with part segregation (sign bits, fixed-size
 * parts, variable-size parts). The fixed-size part has size 'low' bits.
 * The ignored bits in the last byte are set to 0, and their number is
 * written in *num_ignored (0 to 7). The total number of written bytes
 * is returned.
 *
 * If the encoded size would exceed dst_len, then the process fails
 * and the function returns 0.
 */
static size_t
encode_gr(unsigned logn, void *restrict dst, size_t dst_len,
	const int16_t *restrict a, int low, int *num_ignored)
{
	size_t n = (size_t)1 << logn;
	uint8_t *buf = (uint8_t *)dst;
	size_t buf_len = dst_len;
	if (buf_len < ((size_t)(low + 1) << (logn - 3))) {
		return 0;
	}

	/* Sign bits */
	for (size_t u = 0; u < n; u += 8) {
		unsigned x = 0;
		for (size_t v = 0; v < 8; v ++) {
			x |= (*(const uint16_t *)(a + u + v) >> 15) << v;
		}
		buf[u >> 3] = x;
	}
	buf += (n >> 3);
	buf_len -= (n >> 3);

	/* Fixed-size parts */
	uint32_t low_mask = ((uint32_t)1 << low) - 1;
	if (low <= 8) {
		for (size_t u = 0; u < n; u += 8) {
			uint64_t x = 0;
			for (size_t v = 0, vv = 0; v < 8; v ++, vv += low) {
				uint32_t w = (uint32_t)a[u + v];
				w ^= tbmask(w);
				x |= (uint64_t)(w & low_mask) << vv;
			}
			for (int i = 0; i < (low << 3); i += 8) {
				*buf ++ = (uint8_t)(x >> i);
			}
		}
	} else {
		for (size_t u = 0; u < n; u += 8) {
			uint64_t x0 = 0;
			for (size_t v = 0, vv = 0; v < 4; v ++, vv += low) {
				uint32_t w = (uint32_t)a[u + v];
				w ^= tbmask(w);
				x0 |= (uint64_t)(w & low_mask) << vv;
			}
			uint64_t x1 = 0;
			for (size_t v = 4, vv = 0; v < 8; v ++, vv += low)
			{
				uint32_t w = (uint32_t)a[u + v];
				w ^= tbmask(w);
				x1 |= (uint64_t)(w & low_mask) << vv;
			}
			x0 |= x1 << (low << 2);
			x1 >>= 64 - (low << 2);
			for (int i = 0; i < 64; i += 8) {
				*buf ++ = (uint8_t)(x0 >> i);
			}
			for (int i = 0; i < (low << 3) - 64; i += 8) {
				*buf ++ = (uint8_t)(x1 >> i);
			}
		}
	}
	buf_len -= (size_t)low << (logn - 3);

	/* Variable-size parts */
	uint32_t acc = 0;
	int acc_len = 0;
	for (size_t u = 0; u < n; u ++) {
		uint32_t w = (uint32_t)a[u];
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
	if (num_ignored != NULL) {
		*num_ignored = (unsigned)-acc_len & 7;
	}

	return dst_len - buf_len;
}

/*
 * Encode the public key. Returned value is 1 on success, 0 on error;
 * an error is returned if the encoded key size would exceed the fixed
 * public key size (HAWK_PUBKEY_SIZE(logn)).
 *
 * Note: this function temporarily modifies q00[0], but resets it to
 * its original value afterwards.
 */
static int
encode_public(unsigned logn,
	void *restrict dst, size_t dst_len,
	int16_t *restrict q00, const int16_t *restrict q01)
{
	/*
	 * General format:
	 *   q00
	 *   q01
	 *   padding
	 * q00 and q01 both use Golomb-Rice coding.
	 *
	 * Special handling of q00[0]: since it has a larger possible
	 * range than the rest of the coefficients, it is temporarily
	 * downscaled (q00[0] is modified, but the original value is put
	 * back afterwards). The extra bits are appended at the end of the
	 * encoding of q00.
	 */

	int low00 = low_bits_q00[logn];
	int low01 = low_bits_q01[logn];
	int eb00_len = 16 - (low00 + 4);
	uint8_t *buf = (uint8_t *)dst;
	size_t buf_len = dst_len;

	/* q00 */
	int ni;
	int sav_q00 = q00[0];
	q00[0] >>= eb00_len;
	size_t len00 = encode_gr(logn - 1, buf, buf_len, q00, low00, &ni);
	q00[0] = sav_q00;
	if (len00 == 0) {
		return 0;
	}
	/* Extra bits of q00[0] */
	uint32_t eb00 = (uint32_t)sav_q00 & (((uint32_t)1 << eb00_len) - 1);
	if (eb00_len <= ni) {
		buf[len00 - 1] |= eb00 << (8 - ni);
	} else {
		if (len00 >= buf_len) {
			return 0;
		}
		buf[len00 - 1] |= eb00 << (8 - ni);
		buf[len00] = eb00 >> ni;
		len00 ++;
	}
	buf += len00;
	buf_len -= len00;

	size_t len01 = encode_gr(logn, buf, buf_len, q01, low01, NULL);
	if (len01 == 0) {
		return 0;
	}
	buf += len01;
	buf_len -= len01;

	/* Padding to the requested length. */
	memset(buf, 0, buf_len);
	return 1;
}

/* see hawk.h */
int
Zh(keygen)(unsigned logn, void *restrict priv, void *restrict pub,
	hawk_rng rng, void *restrict rng_context,
	void *restrict tmp, size_t tmp_len)
{
	if (logn < 8 || logn > 10) {
		return 0;
	}
	size_t n = (size_t)1 << logn;
	if (tmp_len < 7 + 2 * n) {
		return 0;
	}
	int8_t *f = (int8_t *)(((uintptr_t)tmp + 7) & ~(uintptr_t)7);
	int8_t *g = f + n;
	int8_t *tt8 = g + n;
	int8_t *F = tt8;
	int8_t *G = F + n;
	int16_t *q00 = (int16_t *)(G + n);
	int16_t *q01 = q00 + n;
	int32_t *q11 = (int32_t *)(q01 + n);
	uint8_t *seed = (uint8_t *)(q11 + n);
	size_t seed_len = 8 + ((size_t)1 << (logn - 5));
	size_t priv_len = HAWK_PRIVKEY_SIZE(logn);
	size_t pub_len = HAWK_PUBKEY_SIZE(logn);
	uint8_t *tpriv = seed + seed_len;
	uint8_t *tpub = tpriv + priv_len;
	for (;;) {
		if (Hawk_keygen(logn, f, g, 0, 0, 0, 0, 0, 0, rng, rng_context,
			tt8, (size_t)(((int8_t *)tmp + tmp_len) - tt8)) != 0)
		{
			return 0;
		}

		if (encode_public(logn, tpub, pub_len, q00, q01)) {
			(void)encode_private(logn, tpriv,
				seed, F, G, tpub, pub_len);
#if HAWK_DEBUG
			printf("#### Keygen (n=%u):\n", 1u << logn);
			print_blob("kgseed", seed, seed_len);
			print_i8(logn, "f", f);
			print_i8(logn, "g", g);
			print_i8(logn, "F", F);
			print_i8(logn, "G", G);
			print_i16(logn, "q00", q00);
			print_i16(logn, "q01", q01);
			print_i32(logn, "q11", q11);
			print_blob("priv", tpriv, priv_len);
			print_blob("pub", tpub, pub_len);
#endif
			if (priv != NULL) {
				memcpy(priv, tpriv, priv_len);
			}
			if (pub != NULL) {
				memcpy(pub, tpub, pub_len);
			}
			memmove(tmp, tpriv, priv_len + pub_len);
			return 1;
		}
	}
}
