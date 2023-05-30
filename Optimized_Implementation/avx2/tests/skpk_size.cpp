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
	#include "../hawk_kgen.c"
}

uint8_t gr_buffer[1 << 16];
const int nthreads = 4, num_keygen = 1'000 / nthreads;

/*
 * Returns the number of bytes used in the encoding of this public key.
 *
 * Note: this function temporarily modifies q00[0], but resets it to
 * its original value afterwards.
 */
static int
number_bits_encode_public(unsigned logn,
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

	/* q00 */
	int ni;
	int sav_q00 = q00[0];
	q00[0] >>= eb00_len;
	size_t len00 = encode_gr(logn - 1, gr_buffer, 1 << 16, q00, low00, &ni);
	q00[0] = sav_q00;
	assert(len00 != 0);

	/* Extra bits of q00[0] */
	if (eb00_len <= ni) {
	} else {
		len00 ++;
	}

	size_t len01 = encode_gr(logn, gr_buffer, 1 << 16, q01, low01, NULL);
	assert(len01 != 0);

	return len00 + len01;
}

/* Taken from hawk_gen.c */
/* see hawk.h */
int
mock_hawk_keygen(unsigned logn, hawk_rng rng, void *rng_context, void *tmp,
	size_t tmp_len)
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
	assert(Hawk_keygen(logn, f, g, 0, 0, 0, 0, 0, 0, rng, rng_context, tt8,
		(size_t)(((int8_t *)tmp + tmp_len) - tt8)) == 0);

	return number_bits_encode_public(logn, q00, q01);
}


struct WorkerResult {
	long long iterations;
	long long pksum, pksqsum, pkmin, pkmax;

	WorkerResult() : iterations(0),
		pksum(0), pksqsum(0), pkmin(1000000), pkmax(0) {}

	void combine(const WorkerResult &res) {
		iterations += res.iterations;

		pksum += res.pksum;
		pksqsum += res.pksqsum;
		if (res.pkmin < pkmin) pkmin = res.pkmin;
		if (res.pkmax > pkmax) pkmax = res.pkmax;
	}
};

WorkerResult tot[11];
std::mutex mx;

void work(unsigned logn, const unsigned char *seed)
{
	WorkerResult result;
	uint8_t tmp[HAWK_TMPSIZE_KEYGEN(10)];
	shake_context rng;

	// Initialize a RNG.
	shake_init(&rng, 256);
	shake_inject(&rng, seed, 48);
	shake_flip(&rng);

	result.iterations = num_keygen;
	for (size_t i = 0; i < num_keygen; i++) {
		// Generate key pair.
		int pk_sz = mock_hawk_keygen(logn, (hawk_rng)&shake_extract, &rng, tmp, sizeof tmp);

		result.pksum += pk_sz;
		result.pksqsum += pk_sz * pk_sz;
		if (pk_sz < result.pkmin) result.pkmin = pk_sz;
		if (pk_sz > result.pkmax) result.pkmax = pk_sz;
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

	printf("Total number of iterations: %lld\n", (long long)nthreads * num_keygen);
	printf("degree  private key    public key\n");
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

		// Public key
		int reps = tot[logn].iterations;
		double avg = (double) tot[logn].pksum / reps;
		double std = sqrt((double) tot[logn].pksqsum / reps - avg*avg);
		printf("%4u:   %11u    %7.2f (%5.2f)\n",
			1u << logn, HAWK_PRIVKEY_SIZE(logn), avg, std);
	}

	return 0;
}
