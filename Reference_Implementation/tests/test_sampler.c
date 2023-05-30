/*
 * Verify if the sampling procedures in key generation and signature generation are distributed as
 * is specified in https://eprint.iacr.org/2022/1155.
 *
 *   logn           8     9    10
 *   sigma_sign 1.010 1.278 1.299
 *
 * For key generation, check that the distributions for the coefficients of f and g follow a
 * centred binomial distribution (with support [-eta, eta]) where eta is specified by:
 *   logn  8  9 10
 *   eta   2  4  8
 */

#include <assert.h>
#include <math.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "../sha3.h"
#include "../hawk_sign.c"

#define NUM_SAMPLES ((int64_t)(32 * 1024))

/*
 * We sample the distribution and keep some slack for the difference with the expected
 * probabilities, depending on the number of samples as we do not get exactly the same probability
 * but an approximation of it.
 */
#define EPS(logn) ((FT)(2.0 / sqrt(NUM_SAMPLES << (2 << logn))))

// #define VERBOSE

typedef double FT;

int sk_eta(unsigned logn) {
	if (8 <= logn && logn <= 10) return (1u << (logn - 7));
	assert(0 && "unsupported logn");
}

FT sigma_sign(unsigned logn) {
	if (logn ==  8) return 1.010;
	if (logn ==  9) return 1.278;
	if (logn == 10) return 1.299;
	assert(0 && "unsupported logn");
}

FT factorial(int n) { return n <= 1 ? 1.0 : factorial(n - 1) * n; }

FT binom_pdf(int eta, int x) {
	return factorial(2 * eta) / factorial(eta + x) / factorial(eta - x) / (1 << (2*eta));
}

FT rho(FT x, FT sigma) {
	return exp(-x * x / (2.0 * sigma * sigma));
}

int8_t x[2 * 1024];
uint8_t t[2 * 1024 / 8];

void test_keygen_sampler(shake_context *rng)
{
	FT P[100];
	int freq[100];
	uint8_t seed_buf[40];

	for (unsigned logn = 8; logn <= 10; logn++) {
		size_t seed_len = 8 + ((size_t)1 << (logn - 5));
		int eta = sk_eta(logn);

		for (int i = -eta; i <= eta; i++) {
			P[i + 50] = binom_pdf(eta, i);
		}


		memset(freq, 0, sizeof freq);
		for (int i = NUM_SAMPLES; i--; ) {
			/*
			 * Generate f and g.
			 */
			shake_extract(rng, seed_buf, seed_len);
			Hawk_regen_fg(logn, x, x + (1 << logn), seed_buf);

			for (size_t j = 0; j < (size_t)(2 << logn); j++) {
				freq[x[j] + 50]++;
			}
		}

		int64_t total_samples = NUM_SAMPLES << (1 + logn);
		FT max_abs_diff = 0.0;
		for (int i = -eta; i <= eta; i++) {
			FT found = (FT) freq[i + 50] / total_samples, expected = P[i + 50];

			FT abs_diff = fabs(found - expected);
			if (abs_diff > max_abs_diff)
				max_abs_diff = abs_diff;
		}

		printf("Keygen sampler (logn=%2d) has abs.diff. < %.5f\n", (int) logn, max_abs_diff);
#ifdef VERBOSE
		printf("P(X=n) ");
		for (int i = -eta; i <= eta; i++) {
			printf("%8d ", i);
		}
		printf("\npred   ");
		for (int i = -eta; i <= eta; i++) {
			printf("%8.6f ", P[i + 50]);
		}
		printf("\nfound  ");
		for (int i = -eta; i <= eta; i++) {
			printf("%8.6f ", (FT)freq[i + 50] / total_samples);
		}
		printf("\n\n");
#endif
		assert(max_abs_diff < EPS(logn));
	}
}

void test_sign_sampler(shake_context *rng)
{
	FT P[100] = {};
	int freq[100] = {};

	for (uint8_t coset = 0; coset < 2; coset++) {
		memset(t, coset * 255u, sizeof t);

		for (unsigned logn = 8; logn <= 10; logn++) {
			for (size_t j = 0; j < (size_t)(1 << logn); j++)
				t[j] = 255u * coset;
			// Signing sampler:
			FT norm = 0;
			for (int i = -50; i < 50; i++) {
				// sample from 2Z + coset by scaling everything up by a factor of two
				P[i + 50] = (i + coset) % 2 == 0 ? rho(i, 2.0 * sigma_sign(logn)) : 0.0;
				norm += P[i + 50];
			}

			// normalize
			for (int i = -50; i < 50; i++) P[i + 50] /= norm;

			memset(freq, 0, sizeof freq);

			for (int i = NUM_SAMPLES; i--; ) {
				sig_gauss(logn, (hawk_rng)&shake_extract, rng, NULL, x, t);
				for (size_t j = 0; j < (size_t)(2 << logn); j++)
					freq[x[j] + 50]++;
			}

			int64_t total_samples = NUM_SAMPLES << (1 + logn);

			FT max_abs_diff = 0.0;
			for (int i = -50; i < 50; i++) if (freq[i + 50]) {
				FT found = (FT) freq[i + 50] / total_samples, expected = P[i + 50];

				FT abs_diff = fabs(found - expected);
				if (abs_diff > max_abs_diff)
					max_abs_diff = abs_diff;
			}

			printf("Sign sampler (support 2Z + %d, logn=%2d) has abs.diff. < %.5f\n",
				(int) coset, (int) logn, max_abs_diff);
#ifdef VERBOSE
			printf("P(X=n) ");
			for (int i = -50; i < 50; i++) if (freq[i + 50]) {
				printf("%8d ", i);
			}
			printf("\npred   ");
			for (int i = -50; i < 50; i++) if (freq[i + 50]) {
				printf("%8.6f ", P[i + 50]);
			}
			printf("\nfound  ");
			for (int i = -50; i < 50; i++) if (freq[i + 50]) {
				printf("%8.6f ", (FT)freq[i + 50] / total_samples);
			}
			printf("\n\n");
#endif
			assert(max_abs_diff < EPS(logn));
		}
	}

}

int main()
{
	shake_context rng;

	/* This is just for tests: we can initialize the RNG with the
	   current time, because security does not matter for tests. */
	uint64_t tq = (uint64_t)time(NULL);
	shake_init(&rng, 256);
	shake_inject(&rng, &tq, sizeof tq);
	shake_flip(&rng);

	test_keygen_sampler(&rng);
	test_sign_sampler(&rng);
	return 0;
}
