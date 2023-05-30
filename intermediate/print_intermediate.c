#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include "hawk.h"

int
main(int argc, char *argv[])
{
	unsigned logn;
	int diversifier = 0;

	if (argc >= 2) {
		logn = (unsigned)atoi(argv[1]);
		if (logn < 8 || logn > 10) {
			fprintf(stderr, "Invalid log(degree)\n");
			exit(EXIT_FAILURE);
		}
		if (argc >= 3) {
			diversifier = atoi(argv[2]);
		}
	} else {
		logn = 9;
	}

	/*
	 * RNG is initialized with a reproducible seed (this is for debug
	 * only).
	 */
	char rngseed[30];
	sprintf(rngseed, "rng %u %d", logn, diversifier);
	size_t rngseed_len = strlen(rngseed);

	shake_context rc;
	shake_init(&rc, 256);
	shake_inject(&rc, rngseed, rngseed_len);
	shake_flip(&rc);
	hawk_rng rng = (hawk_rng)&shake_extract;

	/*
	 * Data to sign.
	 */
	char data[30];
	sprintf(data, "data %u %d", logn, diversifier);
	size_t data_len = strlen(data);

	static uint8_t tmp[HAWK_TMPSIZE_KEYGEN(10)];
	static uint8_t priv[HAWK_PRIVKEY_SIZE(10)];
	static uint8_t pub[HAWK_PUBKEY_SIZE(10)];
	static uint8_t sig[HAWK_SIG_SIZE(10)];
	size_t pub_len = HAWK_PUBKEY_SIZE(logn);
	size_t sig_len = HAWK_SIG_SIZE(logn);

	if (!hawk_keygen(logn, priv, pub, rng, &rc, tmp, sizeof tmp)) {
		fprintf(stderr, "Keygen error\n");
		exit(EXIT_FAILURE);
	}
	shake_context scd;
	hawk_sign_start(&scd);
	shake_inject(&scd, data, data_len);
	if (!hawk_sign_finish(logn, rng, &rc, sig,
		&scd, priv, tmp, sizeof tmp))
	{
		fprintf(stderr, "Sign error\n");
		exit(EXIT_FAILURE);
	}
	hawk_verify_start(&scd);
	shake_inject(&scd, data, data_len);
	if (!hawk_verify_finish(logn, sig, sig_len,
		&scd, pub, pub_len, tmp, sizeof tmp))
	{
		fprintf(stderr, "Verify error\n");
		exit(EXIT_FAILURE);
	}

	return 0;
}
