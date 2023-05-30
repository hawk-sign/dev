#include <cassert>
#include <climits>
#include <cmath>
#include <cstdio>
#include <cstring>
#include <mutex>
#include <thread>

// x86_64 specific:
#include<time.h>

extern "C" {
	#define restrict
	#include "../hawk.h"
	#include "../hawk_sign.c"
}

typedef long long ll;

const int nthreads = 4, num_keygen = 1'000 / nthreads, num_sign = 1000;

/* Taken from AVX2 optimized implementation of hawk_sign.c */
TARGET_AVX2
static int
mock_sign_finish(unsigned logn, void (*rng)(void *ctx, void *dst, size_t len),
	void *rng_context, int16_t *output_s1_and_salt, const shake_context *sc_data, const void *priv,
	void *tmp, size_t tmp_len)
{
	int use_shake = 1;
	size_t priv_len = HAWK_PRIVKEY_SIZE(logn);

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
	 *   sigma_ver          1.040     1.425    1.572
	 *   sigma_sec          1.042     1.425    1.974
	 *   sigma_pk             1.1       1.5      2.0
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
		max_xnorm = 2215;
		break;
	case 9:
		salt_len = 24;
		max_xnorm = 8317;
		break;
	case 10:
		salt_len = 40;
		max_xnorm = 20243;
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
		const uint8_t *secbuf = (uint8_t *)priv;
		Hawk_regen_fg(logn, f, g, secbuf);
		F2 = secbuf + seed_len;
		G2 = F2 + (n >> 3);
		hpub = G2 + (n >> 3);
	}

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

		/*
		 * h <- SHAKE256(hm || salt)  (out: 2*n bits)
		 */
		shake_init(&scd, 256);
		shake_inject(&scd, hm, sizeof hm);
		shake_inject(&scd, salt, salt_len);
		shake_flip(&scd);
		shake_extract(&scd, h0, n >> 2);

		/*
		 * t <- B*h  (mod 2)
		 */
		extract_lowbit(logn, f2, f);
		extract_lowbit(logn, g2, g);
		basis_m2_mul(logn, t0, t1, h0, h1, f2, g2, F2, G2, xx);

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
		for (size_t u = 0; u < n; u += 16) {
			__m256i y1 = _mm256_loadu_si256((__m256i *)&w1[u]);
			__m256i y2 = _mm256_loadu_si256((__m256i *)&w2[u]);
			y1 = mq18433_montymul_x16(y1, y2);
			_mm256_storeu_si256((__m256i *)&w1[u], y1);
		}

		/* w3 <- 2*(f*x1 - g*x0) = h1 - 2*s1 */
		mq18433_poly_set_small(logn, w2, x1);
		if (priv_decoded) {
			mq18433_poly_set_small(logn, w3, f);
		} else {
			mq18433_poly_set_small_inplace_high(logn, w3);
		}
		mq18433_NTT(logn, w2);
		mq18433_NTT(logn, w3);
		for (size_t u = 0; u < n; u += 16) {
			__m256i y1 = _mm256_loadu_si256((__m256i *)&w1[u]);
			__m256i y2 = _mm256_loadu_si256((__m256i *)&w2[u]);
			__m256i y3 = _mm256_loadu_si256((__m256i *)&w3[u]);
			y3 = mq18433_tomonty_x16(mq18433_sub_x16(
				mq18433_montymul_x16(y2, y3), y1));
			_mm256_storeu_si256((__m256i *)&w3[u], y3);
		}
		mq18433_iNTT(logn, w3);
		mq18433_poly_snorm(logn, w3);

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
		int lim = 1 << ((logn == 10) ? 10 : 9);
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

		/*
		 * We have the signature (in s1). Put it in output_s1_and_salt and don't check
		 * if it encodes in a small enough signature.
		 */
		memcpy(output_s1_and_salt, s1, n * sizeof(int16_t));
		memcpy(&output_s1_and_salt[n], salt, salt_len);
		return 1;

		/* size_t sig_len = HAWK_SIG_SIZE(logn);
		if (encode_sig(logn, tmp, sig_len, salt, salt_len, s1)) {
			if (sig != NULL) {
				memcpy(sig, tmp, sig_len);
			}
			return 1;
		} */
	}
}

/*
 * The following function is taken from the Reference Implementation of hawk_sign.c.
 * It "fakes" encoding the signature, and only remembers the number of output bits.
 */
static int
number_bits_encode_sig(unsigned logn, size_t salt_len, const int16_t *s1)
{
	size_t n = (size_t)1 << logn;
	int low = (logn == 10) ? 6 : 5;
	size_t sig_len = 0;

	/* Salt */
	sig_len += salt_len;

	/* Sign bits */
	sig_len += (n >> 3);

	/* Fixed-size parts */
	sig_len += (size_t)low << (logn - 3);

	/* Variable-size parts */
	int acc_len = 0;
	for (size_t u = 0; u < n; u ++) {
		uint32_t w = (uint32_t)s1[u];
		int k = (int)((w ^ tbmask(w)) >> low);
		acc_len += 1 + k;
		while (acc_len >= 8) {
			sig_len ++;
			acc_len -= 8;
		}
	}

	/* total number of bits used: */
	return 8 * sig_len + acc_len;
}


struct WorkerResult {
	long long iterations, encode_fails, recovery_fails;
	long long sum_sizes, sum_square_sizes;

	WorkerResult() : iterations(0), encode_fails(0), recovery_fails(0),
		sum_sizes(0), sum_square_sizes(0) {}

	void combine(const WorkerResult &res) {
		iterations += res.iterations;
		encode_fails += res.encode_fails;
		recovery_fails += res.recovery_fails;
		sum_sizes += res.sum_sizes;
		sum_square_sizes += res.sum_square_sizes;
	}
};

WorkerResult tot[11];
std::mutex mx;

void work(unsigned logn, const unsigned char *seed)
{
	WorkerResult result;
	uint8_t tmp[HAWK_TMPSIZE_KEYGEN(10)];
	uint8_t sec_key[HAWK_PRIVKEY_SIZE(10)];
	uint8_t pub_key[HAWK_PUBKEY_SIZE(10)];
	uint8_t sig[HAWK_SIG_SIZE(10)];
	int16_t s1_and_salt[40 + (1 << 10)];
	shake_context rng, sc_data;

	// Initialize a RNG.
	shake_init(&rng, 256);
	shake_inject(&rng, seed, 48);
	shake_flip(&rng);

	size_t salt_len;
	switch (logn) {
		case  8: salt_len = 14; break;
		case  9: salt_len = 24; break;
		case 10: salt_len = 40; break;
		default: exit(1);
	}

	result.iterations = num_keygen * num_sign;
	for (int kg = 0; kg < num_keygen; kg++) {
		hawk_keygen(logn, sec_key, pub_key, (hawk_rng)&shake_extract, &rng, tmp, sizeof tmp);
		for (int s = 0; s < num_sign; s++) {
			// make a signature of a random message...
			hawk_sign_start(&sc_data);
			shake_extract(&rng, tmp, 48);
			shake_inject(&sc_data, tmp, 48);

			// Compute the signature.
			assert(mock_sign_finish(logn, (hawk_rng)&shake_extract, &rng, s1_and_salt, &sc_data, sec_key, tmp, sizeof tmp) == 1);

			int bits_sig = number_bits_encode_sig(logn, salt_len, s1_and_salt);
			assert(bits_sig != 0);
			result.sum_sizes += bits_sig;
			result.sum_square_sizes += bits_sig * bits_sig;

			if (!encode_sig(logn, sig, HAWK_SIG_SIZE(logn), (uint8_t *)(&s1_and_salt[1<<logn]), salt_len, s1_and_salt)) {
				result.encode_fails++;
				continue;
			}

			assert(hawk_decode_signature(logn, s1_and_salt, (const void *)&sig, HAWK_SIG_SIZE(logn)) == 1);
			int res = hawk_verify_finish(logn, &sig, HAWK_SIG_SIZE(logn), &sc_data, &pub_key, HAWK_PUBKEY_SIZE(logn), &tmp, sizeof tmp);
			if (res == 0) {
				result.recovery_fails++;
			}
		}
	}

	/* acquire mutex lock */ {
		std::lock_guard<std::mutex> guard(mx);
		tot[logn].combine(result);
	}
}

int main()
{
	shake_context rng;
	unsigned char seeds[nthreads * 48];
	std::thread* pool[nthreads - 1];

	/* This is just for tests: we can initialize the RNG with the
	   current time, because security does not matter for tests. */
	uint64_t tq = (uint64_t)time(NULL);
	shake_init(&rng, 256);
	shake_inject(&rng, &tq, sizeof tq);
	shake_flip(&rng);

	shake_extract(&rng, seeds, nthreads * 48);

	printf("Total number of iterations: %lld\n", (long long)nthreads * num_keygen * num_sign);
	printf("logn #bytes           5 sigma\n");
	for (unsigned logn = 8; logn <= 10; logn++) {
		tot[logn] = WorkerResult();
		for (int i = 0; i < nthreads-1; i++) {
			pool[i] = new std::thread(work, logn, seeds + 48 * i);
		}
		work(logn, seeds + (nthreads - 1) * 48);
		for (int i = 0; i < nthreads-1; i++) {
			pool[i]->join();
			delete pool[i];
		}

		long long iters = tot[logn].iterations - tot[logn].encode_fails;
		double avg_sz = (double)tot[logn].sum_sizes / iters;
		double std_sz = sqrt((double)tot[logn].sum_square_sizes / iters - avg_sz * avg_sz);
		printf("%4d %7.2f (%5.3f) %8.3f\n",
			(int) logn, avg_sz / 8.0, std_sz / 8.0, (avg_sz + 5.0 * std_sz) / 8.0);
	}

	printf("\n");
	for (unsigned logn = 8; logn <= 10; logn++) {
		long long iters = tot[logn].iterations - tot[logn].encode_fails;
		if (tot[logn].encode_fails != 0) {
			printf("!!! %lld out of %lld signatures were too large for encoding (logn=%2d) !!!\n",
					tot[logn].encode_fails, tot[logn].iterations, logn);
		}

		if (tot[logn].recovery_fails != 0) {
			printf("!!! %lld out of %lld signatures failed verification (logn=%2d) !!!\n",
					tot[logn].recovery_fails, iters, logn);
		}
	}

	return 0;
}
