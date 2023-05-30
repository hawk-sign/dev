/*
 * Test if encoding and decoding works for the secret key, public key and signature.  In addition,
 * it gives a (rough) percentage of the key pairs with a public key that can be encoded succesfully
 * within the specified size limit of HAWK_PUBKEY_SIZE(logn).
 */

#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#include "../hawk.h"
#include "../hawk_kgen.c"

#define LOGN (10)
#define N (1 << LOGN)
#define BUFLEN (1 << 20)
#define NUM_SAMPLES (1000)

uint8_t b[HAWK_TMPSIZE_KEYGEN(LOGN)], buf1[BUFLEN], buf2[BUFLEN], buf3[BUFLEN];
uint8_t sig[HAWK_SIG_SIZE(LOGN)], Fmod2[N/8], Gmod2[N/8];
int8_t f[N], g[N], F[N], G[N];
int16_t q00[N], q01[N], q00q012[HAWK_DECODED_PUB_LENGTH(LOGN)];
int32_t q11[N];

size_t test_encode_decode(unsigned logn, shake_context *rng) {
	shake_context sc;
	size_t n = 1 << logn;
	uint8_t seed_buf[40];

	uintptr_t utmp1 = (uintptr_t)b, utmp2 = (utmp1 + 7) & ~(uintptr_t)7;
	uint32_t *tt32 = (void *)utmp2;
	int16_t *s1 = ((int16_t *)tt32) + 2 * n;

	size_t num_runs = 0;
	for (int i = 0, encodable; i < NUM_SAMPLES; i++) {
		do {
			/*
			 * Generate a key pair.
			 */
			Hawk_keygen(logn, f, g, F, G, q00, q01, q11,
				seed_buf, (hawk_rng)&shake_extract, rng, b, sizeof b);

			/*
			 * Test if encoding the public key works.
			 * There is a small probability that the public key does not fit in the specified length.
			 */
			encodable = encode_public(logn, buf2, HAWK_PUBKEY_SIZE(logn), q00, q01);
			printf("%d", encodable);
			fflush(stdout);
			num_runs++;
		} while (!encodable);

		/*
		 * Hash the public key.
		 */
		uint8_t hpk[40];
		size_t hpk_len = 8 + (1 << (logn - 5));
		shake_init(&sc, 256);
		shake_inject(&sc, buf2, HAWK_PUBKEY_SIZE(logn));
		shake_flip(&sc);
		shake_extract(&sc, hpk, hpk_len);

		/*
		 * Test if decoding the public key gives the same q00 and q01.
		 */
		hawk_decode_public_key(logn, q00q012, buf2, HAWK_PUBKEY_SIZE(logn));
		assert(memcmp(q00, q00q012, n) == 0);
		assert(memcmp(q01, q00q012 + n/2, 2*n) == 0);
		assert(memcmp(hpk, q00q012 + n + n/2, hpk_len) == 0);

		/*
		 * Test if q11 can be succesfully recovered?
		 */
		/* TODO */

		/*
		 * Test if encoding the secret key works.
		 * Note: this overwrites the encoded public key.
		 */
		assert(encode_private(logn, buf1, seed_buf, F, G, buf2, HAWK_PUBKEY_SIZE(logn)) == HAWK_PRIVKEY_SIZE(logn));

		/*
		 * Test if decoding the secret key gives the same (f, g, F (mod 2), G (mod 2), H(pk)).
		 */
		hawk_decode_private_key(logn, buf2, buf1);
		extract_lowbit(logn, Fmod2, F);
		extract_lowbit(logn, Gmod2, G);
		int8_t *f2 = (int8_t *)&buf2[0], *g2 = f2 + n;
		uint8_t *Fmod22 = &buf2[2*n], *Gmod22 = Fmod22 + (n/8);
		uint8_t *hpk2 = Gmod22 + (n/8);

		// Check if f and g are the same.
		assert(memcmp(f, f2, n) == 0 && memcmp(g, g2, n) == 0);

		// Check if F (mod 2) and G (mod 2) are the same.
		assert(memcmp(Fmod2, Fmod22, n/8) == 0 && memcmp(Gmod2, Gmod22, n/8) == 0);

		// Check if H(pk) from the private key matches the public key.
		assert(memcmp(hpk, hpk2, hpk_len) == 0);

		/*
		 * Prepare a signature
		 */
		hawk_sign_start(&sc);
		shake_extract(rng, b, 48);
		shake_inject(&sc, b, 48);
		hawk_sign_finish(logn, (hawk_rng)&shake_extract, rng, buf2, &sc, buf1, b, sizeof b);

		/*
		 * Test if encoding of signatures works.
		 */
		hawk_decode_signature(logn, (int16_t *)buf3, buf2, HAWK_SIG_SIZE(logn));
		assert(memcmp(buf3, s1, 2 * n) == 0);

		/*
		 * Test if s0 can be succesfully recovered?
		 */
		/* TODO */
	}

	return num_runs;
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

	size_t num_runs[LOGN + 1];

	for (unsigned logn = 8; logn <= LOGN; logn++) {
		printf("%2u: ", logn);
		fflush(stdout);

		num_runs[logn] = test_encode_decode(logn, &rng);
		printf("\n");
	}

	printf("\nlogn             ");
	for (unsigned logn = 8; logn <= LOGN; logn++) {
		printf(" hawk-%4d", 1 << logn);
	}
	printf("\n");
	printf("Pr. pk encodable ");
	for (unsigned logn = 8; logn <= LOGN; logn++) {
		printf( "%9.2f%%", (double)100.0 * NUM_SAMPLES / num_runs[logn]);
	}
	printf("\n");

	return 0;
}
