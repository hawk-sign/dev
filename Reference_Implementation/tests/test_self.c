#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>

#include "../hawk.h"

#if defined _MSC_VER
#pragma warning( disable : 4146 )
#pragma warning( disable : 4244 )
#pragma warning( disable : 4267 )
#pragma warning( disable : 4334 )
#endif

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

static size_t
hextobin(uint8_t *buf, size_t max_len, const char *src)
{
	size_t u;
	int acc, z;

	u = 0;
	acc = 0;
	z = 0;
	for (;;) {
		int c;

		c = *src ++;
		if (c == 0) {
			if (z) {
				fprintf(stderr, "Lone hex nibble\n");
				exit(EXIT_FAILURE);
			}
			return u;
		}
		if (c >= '0' && c <= '9') {
			c -= '0';
		} else if (c >= 'A' && c <= 'F') {
			c -= 'A' - 10;
		} else if (c >= 'a' && c <= 'f') {
			c -= 'a' - 10;
		} else if (c == ' ' || c == '\t' || c == '\r' || c == '\n') {
			continue;
		} else {
			fprintf(stderr, "Not an hex digit: U+%04X\n",
				(unsigned)c);
			exit(EXIT_FAILURE);
		}
		if (z) {
			if (u >= max_len) {
				fprintf(stderr,
					"Hex string too long for buffer\n");
				exit(EXIT_FAILURE);
			}
			buf[u ++] = (unsigned char)((acc << 4) + c);
		} else {
			acc = c;
		}
		z = !z;
	}
}

#define HEXTOBIN(dst, src)   do { \
		if (hextobin(dst, sizeof(dst), src) != sizeof(dst)) { \
			fprintf(stderr, "Wrong hexdec length\n"); \
			exit(EXIT_FAILURE); \
		} \
	} while (0)

static void
check_eq(const void *a, const void *b, size_t len, const char *banner)
{
	size_t u;

	if (memcmp(a, b, len) == 0) {
		return;
	}
	fprintf(stderr, "%s: wrong value:\n", banner);
	fprintf(stderr, "a: ");
	for (u = 0; u < len; u ++) {
		fprintf(stderr, "%02x", ((const unsigned char *)a)[u]);
	}
	fprintf(stderr, "\n");
	fprintf(stderr, "b: ");
	for (u = 0; u < len; u ++) {
		fprintf(stderr, "%02x", ((const unsigned char *)b)[u]);
	}
	fprintf(stderr, "\n");
	exit(EXIT_FAILURE);
}

/*
 * A perfunctory SHA-1 implementation, for aggregate reproducible tests.
 */
static void
sha1_round_inner(const uint8_t *buf, uint32_t *val)
{
#define F(B, C, D)     ((((C) ^ (D)) & (B)) ^ (D))
#define G(B, C, D)     ((B) ^ (C) ^ (D))
#define H(B, C, D)     (((D) & (C)) | (((D) | (C)) & (B)))
#define I(B, C, D)     G(B, C, D)

#define ROTL(x, n)    (((x) << (n)) | ((x) >> (32 - (n))))

#define K1     ((uint32_t)0x5A827999)
#define K2     ((uint32_t)0x6ED9EBA1)
#define K3     ((uint32_t)0x8F1BBCDC)
#define K4     ((uint32_t)0xCA62C1D6)

	uint32_t m[80];
	for (int i = 0; i < 16; i ++) {
		m[i] = ((uint32_t)buf[(i << 2) + 0] << 24)
			| ((uint32_t)buf[(i << 2) + 1] << 16)
			| ((uint32_t)buf[(i << 2) + 2] << 8)
			| (uint32_t)buf[(i << 2) + 3];
	}
	for (int i = 16; i < 80; i ++) {
		uint32_t x = m[i - 3] ^ m[i - 8] ^ m[i - 14] ^ m[i - 16];
		m[i] = ROTL(x, 1);
	}

	uint32_t a = val[0];
	uint32_t b = val[1];
	uint32_t c = val[2];
	uint32_t d = val[3];
	uint32_t e = val[4];
	for (int i = 0; i < 20; i += 5) {
		e += ROTL(a, 5) + F(b, c, d) + K1 + m[i + 0]; b = ROTL(b, 30);
		d += ROTL(e, 5) + F(a, b, c) + K1 + m[i + 1]; a = ROTL(a, 30);
		c += ROTL(d, 5) + F(e, a, b) + K1 + m[i + 2]; e = ROTL(e, 30);
		b += ROTL(c, 5) + F(d, e, a) + K1 + m[i + 3]; d = ROTL(d, 30);
		a += ROTL(b, 5) + F(c, d, e) + K1 + m[i + 4]; c = ROTL(c, 30);
	}
	for (int i = 20; i < 40; i += 5) {
		e += ROTL(a, 5) + G(b, c, d) + K2 + m[i + 0]; b = ROTL(b, 30);
		d += ROTL(e, 5) + G(a, b, c) + K2 + m[i + 1]; a = ROTL(a, 30);
		c += ROTL(d, 5) + G(e, a, b) + K2 + m[i + 2]; e = ROTL(e, 30);
		b += ROTL(c, 5) + G(d, e, a) + K2 + m[i + 3]; d = ROTL(d, 30);
		a += ROTL(b, 5) + G(c, d, e) + K2 + m[i + 4]; c = ROTL(c, 30);
	}
	for (int i = 40; i < 60; i += 5) {
		e += ROTL(a, 5) + H(b, c, d) + K3 + m[i + 0]; b = ROTL(b, 30);
		d += ROTL(e, 5) + H(a, b, c) + K3 + m[i + 1]; a = ROTL(a, 30);
		c += ROTL(d, 5) + H(e, a, b) + K3 + m[i + 2]; e = ROTL(e, 30);
		b += ROTL(c, 5) + H(d, e, a) + K3 + m[i + 3]; d = ROTL(d, 30);
		a += ROTL(b, 5) + H(c, d, e) + K3 + m[i + 4]; c = ROTL(c, 30);
	}
	for (int i = 60; i < 80; i += 5) {
		e += ROTL(a, 5) + I(b, c, d) + K4 + m[i + 0]; b = ROTL(b, 30);
		d += ROTL(e, 5) + I(a, b, c) + K4 + m[i + 1]; a = ROTL(a, 30);
		c += ROTL(d, 5) + I(e, a, b) + K4 + m[i + 2]; e = ROTL(e, 30);
		b += ROTL(c, 5) + I(d, e, a) + K4 + m[i + 3]; d = ROTL(d, 30);
		a += ROTL(b, 5) + I(c, d, e) + K4 + m[i + 4]; c = ROTL(c, 30);
	}

	val[0] += a;
	val[1] += b;
	val[2] += c;
	val[3] += d;
	val[4] += e;

#undef F
#undef G
#undef H
#undef I
#undef ROTL
#undef K1
#undef K2
#undef K3
#undef K4
}

typedef struct {
	uint8_t buf[64];
	uint32_t val[5];
	uint64_t count;
} sha1_context;

static void
sha1_init(sha1_context *sc)
{
	static const uint32_t IV[5] = {
		0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0
	};

	memset(sc->buf, 0, sizeof sc->buf);
	memcpy(sc->val, IV, sizeof sc->val);
	sc->count = 0;
}

static void
sha1_update(sha1_context *sc, const void *data, size_t len)
{
	const uint8_t *buf = data;
	size_t ptr = (size_t)sc->count & 63;
	sc->count += (uint64_t)len;
	while (len > 0) {
		size_t clen = 64 - ptr;
		if (clen > len) {
			clen = len;
		}
		memcpy(sc->buf + ptr, buf, clen);
		buf += clen;
		len -= clen;
		ptr += clen;
		if (ptr == 64) {
			sha1_round_inner(sc->buf, sc->val);
			ptr = 0;
		}
	}
}

static void
sha1_out(const sha1_context *cc, void *dst)
{
	uint8_t tmp[64];
	uint32_t val[5];

	size_t ptr = (size_t)cc->count & 63;
	memcpy(tmp, cc->buf, ptr);
	memcpy(val, cc->val, sizeof val);
	tmp[ptr ++] = 0x80;
	if (ptr > 56) {
		memset(tmp + ptr, 0, 64 - ptr);
		sha1_round_inner(tmp, val);
		memset(tmp, 0, 56);
	} else {
		memset(tmp + ptr, 0, 56 - ptr);
	}
	uint64_t v = cc->count << 3;
	for (int i = 0; i < 8; i ++) {
		tmp[56 + i] = (uint8_t)(v >> (8 * (7 - i)));
	}
	sha1_round_inner(tmp, val);
	uint8_t *buf = dst;
	for (int i = 0; i < 5; i ++) {
		uint32_t w = val[i];
		buf[(i << 2) + 0] = (uint8_t)(w >> 24);
		buf[(i << 2) + 1] = (uint8_t)(w >> 16);
		buf[(i << 2) + 2] = (uint8_t)(w >> 8);
		buf[(i << 2) + 3] = (uint8_t)w;
	}
}

static void
test_shake256_kat(const char *hexsrc, const char *hexout,
	uint8_t *tmp, size_t tlen)
{
	uint8_t *in = tmp;
	size_t ilen = hextobin(in, tlen, hexsrc);
	uint8_t *ref = in + ilen;
	size_t olen = hextobin(ref, tlen - ilen, hexout);
	uint8_t *out = ref + olen;
	if (tlen < ilen + 2 * olen) {
		fprintf(stderr, "ERR: temporary buffer is too short\n");
		exit(EXIT_FAILURE);
	}

	shake_context sc;

	memset(out, 0, olen);
	shake_init(&sc, 256);
	shake_inject(&sc, in, ilen);
	shake_flip(&sc);
	shake_extract(&sc, out, olen);
	check_eq(ref, out, olen, "KAT 1");

	memset(out, 0, olen);
	shake_init(&sc, 256);
	for (size_t u = 0; u < ilen; u ++) {
		shake_inject(&sc, &in[u], 1);
	}
	shake_flip(&sc);
	for (size_t u = 0; u < olen; u ++) {
		shake_extract(&sc, &out[u], 1);
	}
	check_eq(ref, out, olen, "KAT 2");

	printf(".");
	fflush(stdout);
}

static void
test_shake(void)
{
	printf("Test SHAKE: ");
	fflush(stdout);

	size_t tlen = 1000;
	uint8_t *tmp = xmalloc(tlen);
	test_shake256_kat("", "46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762fd75dc4ddd8c0f200cb05019d67b592f6fc821c49479ab48640292eacb3b7c4be", tmp, tlen);
	test_shake256_kat("dc5a100fa16df1583c79722a0d72833d3bf22c109b8889dbd35213c6bfce205813edae3242695cfd9f59b9a1c203c1b72ef1a5423147cb990b5316a85266675894e2644c3f9578cebe451a09e58c53788fe77a9e850943f8a275f830354b0593a762bac55e984db3e0661eca3cb83f67a6fb348e6177f7dee2df40c4322602f094953905681be3954fe44c4c902c8f6bba565a788b38f13411ba76ce0f9f6756a2a2687424c5435a51e62df7a8934b6e141f74c6ccf539e3782d22b5955d3baf1ab2cf7b5c3f74ec2f9447344e937957fd7f0bdfec56d5d25f61cde18c0986e244ecf780d6307e313117256948d4230ebb9ea62bb302cfe80d7dfebabc4a51d7687967ed5b416a139e974c005fff507a96", "2bac5716803a9cda8f9e84365ab0a681327b5ba34fdedfb1c12e6e807f45284b", tmp, tlen);
	test_shake256_kat("8d8001e2c096f1b88e7c9224a086efd4797fbf74a8033a2d422a2b6b8f6747e4", "2e975f6a8a14f0704d51b13667d8195c219f71e6345696c49fa4b9d08e9225d3d39393425152c97e71dd24601c11abcfa0f12f53c680bd3ae757b8134a9c10d429615869217fdd5885c4db174985703a6d6de94a667eac3023443a8337ae1bc601b76d7d38ec3c34463105f0d3949d78e562a039e4469548b609395de5a4fd43c46ca9fd6ee29ada5efc07d84d553249450dab4a49c483ded250c9338f85cd937ae66bb436f3b4026e859fda1ca571432f3bfc09e7c03ca4d183b741111ca0483d0edabc03feb23b17ee48e844ba2408d9dcfd0139d2e8c7310125aee801c61ab7900d1efc47c078281766f361c5e6111346235e1dc38325666c", tmp, tlen);
	xfree(tmp);

	printf(" done.\n");
	fflush(stdout);
}

static void
test_shake_x4(void)
{
	printf("Test SHAKE-x4: ");
	fflush(stdout);

	shake_context rng;
	shake_init(&rng, 256);
	shake_flip(&rng);

	for (int i = 0; i < 20; i ++) {
		shake_context sc[4];
		for (int j = 0; j < 4; j ++) {
			uint8_t tmp[256];
			shake_extract(&rng, tmp, 1);
			size_t len = tmp[0];
			shake_extract(&rng, tmp, len);
			shake_init(&sc[j], 256);
			shake_inject(&sc[j], tmp, len);
		}
		shake_x4_context scx4;
		shake_x4_flip(&scx4, sc);
		uint64_t ww[4 * 100];
		shake_x4_extract_words(&scx4, ww, 100);

		shake_x4_flip(&scx4, sc);
		for (int k = 0; k < 100; k ++) {
			uint64_t w[4];
			shake_x4_extract_words(&scx4, w, 1);
			for (int j = 0; j < 4; j ++) {
				uint64_t x = w[j];
				uint64_t y = ww[4 * k + j];
				if (x != y) {
					fprintf(stderr, "ERR (buf): k=%d j=%d:"
						" 0x%016llX / 0x%016llX\n",
						k, j,
						(unsigned long long)x,
						(unsigned long long)y);
					exit(EXIT_FAILURE);
				}
			}
		}

		for (int j = 0; j < 4; j ++) {
			shake_flip(&sc[j]);
		}
		for (int k = 0; k < 100; k ++) {
			for (int j = 0; j < 4; j ++) {
				uint8_t tmp[8];
				shake_extract(&sc[j], tmp, 8);
				uint64_t x = (uint64_t)tmp[0]
					| ((uint64_t)tmp[1] << 8)
					| ((uint64_t)tmp[2] << 16)
					| ((uint64_t)tmp[3] << 24)
					| ((uint64_t)tmp[4] << 32)
					| ((uint64_t)tmp[5] << 40)
					| ((uint64_t)tmp[6] << 48)
					| ((uint64_t)tmp[7] << 56);
				uint64_t y = ww[4 * k + j];
				if (x != y) {
					fprintf(stderr, "ERR: k=%d j=%d:"
						" 0x%016llX / 0x%016llX\n",
						k, j,
						(unsigned long long)x,
						(unsigned long long)y);
					exit(EXIT_FAILURE);
				}
			}
		}

		printf(".");
		fflush(stdout);
	}

	printf(" done.\n");
	fflush(stdout);
}

/*
 * Defined in hawk_vrfy.c
 */
int hawk_verify_inner(unsigned logn,
	const void *restrict sig, size_t sig_len,
	const shake_context *restrict scd_data,
	const void *restrict pub, size_t pub_len,
	void *restrict tmp, size_t tmp_len, void *restrict ss);

static void
test_multiple_sigs(unsigned logn, uint32_t num, const char *ref_hv)
{
	printf("%u: ", logn);
	fflush(stdout);

	shake_context rng;
	shake_init(&rng, 256);
	uint8_t seed = (uint8_t)logn;
	shake_inject(&rng, &seed, sizeof seed);
	shake_flip(&rng);

	sha1_context sc;
	sha1_init(&sc);

	size_t n = (size_t)1 << logn;
	size_t priv_len = HAWK_PRIVKEY_SIZE(logn);
	uint8_t *priv = xmalloc(priv_len);
	size_t priv_dec_len = HAWK_PRIVKEY_DECODED_SIZE(logn);
	uint8_t *priv_dec = xmalloc(priv_dec_len);
	size_t pub_len = HAWK_PUBKEY_SIZE(logn);
	uint8_t *pub = xmalloc(pub_len);
	size_t sig_len = HAWK_SIG_SIZE(logn);
	uint8_t *sig = xmalloc(sig_len);
	size_t tmp_len = HAWK_TMPSIZE_KEYGEN(logn);
	uint8_t *tmp = xmalloc(tmp_len);
	uint16_t *ss1 = xmalloc(4 * n + 8);
	uint8_t *ss2 = xmalloc(4 * n + 8);
	int16_t *s1_and_salt = xmalloc(HAWK_DECODED_SIG_LENGTH(logn) * 2);
	int16_t *q00_q01_hpk = xmalloc(HAWK_DECODED_PUB_LENGTH(logn) * 2);

	for (uint32_t snum = 0; snum < num; snum ++) {
		if (!hawk_keygen(logn, priv, pub,
			(hawk_rng)&shake_extract, &rng, tmp, tmp_len))
		{
			fprintf(stderr, "keygen failed\n");
			exit(EXIT_FAILURE);
		}
		sha1_update(&sc, pub, pub_len);

		char data[20];
		sprintf(data, "test%u", snum);
		shake_context sc_data;
		hawk_sign_start(&sc_data);
		shake_inject(&sc_data, data, strlen(data));
		size_t tmp_sig_len = 6 * n;
		((uint32_t *)tmp)[tmp_sig_len >> 2] = 0xA7C083FE;
		((uint32_t *)tmp)[(tmp_sig_len >> 2) - 1] = 0xA7C083FE;
		if (!hawk_sign_finish(logn,
			(hawk_rng)&shake_extract, &rng,
			sig, &sc_data, priv, tmp, tmp_sig_len))
		{
			fprintf(stderr, "sign error\n");
			exit(EXIT_FAILURE);
		}
		if (((uint32_t *)tmp)[tmp_sig_len >> 2] != 0xA7C083FE) {
			fprintf(stderr, "ERR (sign): tmp overrun\n");
			exit(EXIT_FAILURE);
		}
		if (((uint32_t *)tmp)[(tmp_sig_len >> 2) - 1] == 0xA7C083FE) {
			fprintf(stderr, "ERR (sign): buffer overestimated\n");
			exit(EXIT_FAILURE);
		}
		sha1_update(&sc, sig, sig_len);

		size_t tmp_vrfy_len = 10 * n;
		((uint32_t *)tmp)[tmp_vrfy_len >> 2] = 0xA7C083FE;
		((uint32_t *)tmp)[(tmp_vrfy_len >> 2) - 1] = 0xA7C083FE;
		if (!hawk_verify_inner(logn, sig, sig_len, &sc_data,
			pub, pub_len, tmp, tmp_vrfy_len, ss1))
		{
			fprintf(stderr, "verify error\n");
			exit(EXIT_FAILURE);
		}
		for (size_t u = 0; u < (n << 1); u ++) {
			unsigned x = ss1[u];
			ss2[(u << 1) + 0] = (uint8_t)x;
			ss2[(u << 1) + 1] = (uint8_t)(x >> 8);
		}
		for (size_t u = 0; u < 2; u ++) {
			uint32_t x = *(uint32_t *)(ss1 + (n << 1) + (u << 1));
			ss2[(n << 2) + (u << 2) + 0] = (uint8_t)x;
			ss2[(n << 2) + (u << 2) + 1] = (uint8_t)(x >> 8);
			ss2[(n << 2) + (u << 2) + 2] = (uint8_t)(x >> 16);
			ss2[(n << 2) + (u << 2) + 3] = (uint8_t)(x >> 24);
		}
		sha1_update(&sc, ss2, 4 * n + 8);

		if (((uint32_t *)tmp)[tmp_vrfy_len >> 2] != 0xA7C083FE) {
			fprintf(stderr, "ERR (vrfy): tmp overrun\n");
			exit(EXIT_FAILURE);
		}
		if (((uint32_t *)tmp)[(tmp_vrfy_len >> 2) - 1] == 0xA7C083FE) {
			fprintf(stderr, "ERR (vrfy): buffer overestimated\n");
			exit(EXIT_FAILURE);
		}

		if (!hawk_verify_finish(logn, sig, sig_len, &sc_data,
			pub, pub_len, tmp, tmp_vrfy_len))
		{
			fprintf(stderr, "verify error (2)\n");
			exit(EXIT_FAILURE);
		}
		if (((uint32_t *)tmp)[tmp_vrfy_len >> 2] != 0xA7C083FE) {
			fprintf(stderr, "ERR (vrfy 2): tmp overrun\n");
			exit(EXIT_FAILURE);
		}

		if (!hawk_decode_signature(logn, s1_and_salt, sig, sig_len)) {
			fprintf(stderr, "ERR: decode_signature\n");
			exit(EXIT_FAILURE);
		}
		if (!hawk_decode_public_key(logn, q00_q01_hpk, pub, pub_len)) {
			fprintf(stderr, "ERR: decode_public_key\n");
			exit(EXIT_FAILURE);
		}
		if (!hawk_verify_finish(logn, s1_and_salt, (size_t)-1, &sc_data,
			q00_q01_hpk, (size_t)-1, tmp, tmp_vrfy_len))
		{
			fprintf(stderr, "verify error (3)\n");
			exit(EXIT_FAILURE);
		}
		if (((uint32_t *)tmp)[tmp_vrfy_len >> 2] != 0xA7C083FE) {
			fprintf(stderr, "ERR (vrfy 3): tmp overrun\n");
			exit(EXIT_FAILURE);
		}

		sig[sig_len - 1] ^= 0x01;
		if (hawk_verify_finish(logn, sig, sig_len, &sc_data,
			pub, pub_len, tmp, tmp_vrfy_len))
		{
			fprintf(stderr, "invalid signature did not fail (1)\n");
			exit(EXIT_FAILURE);
		}
		sig[sig_len - 1] ^= 0x01;
		if (!hawk_verify_finish(logn, sig, sig_len, &sc_data,
			pub, pub_len, tmp, tmp_vrfy_len))
		{
			fprintf(stderr, "verify error (4)\n");
			exit(EXIT_FAILURE);
		}

		hawk_verify_start(&sc_data);
		data[0] ^= 0x01;
		shake_inject(&sc_data, data, strlen(data));
		if (hawk_verify_finish(logn, s1_and_salt, (size_t)-1, &sc_data,
			q00_q01_hpk, (size_t)-1, tmp, tmp_vrfy_len))
		{
			fprintf(stderr, "invalid signature did not fail (2)\n");
			exit(EXIT_FAILURE);
		}

		memset(sig, 0, sig_len);
		hawk_decode_private_key(logn, priv_dec, priv);
		hawk_sign_start(&sc_data);
		shake_inject(&sc_data, data, strlen(data));
		if (!hawk_sign_finish_alt(logn,
			(hawk_rng)&shake_extract, &rng,
			sig, &sc_data, priv_dec, priv_dec_len,
			tmp, tmp_sig_len))
		{
			fprintf(stderr, "sign_alt error\n");
			exit(EXIT_FAILURE);
		}
		if (!hawk_verify_finish(logn, sig, sig_len, &sc_data,
			pub, pub_len, tmp, tmp_vrfy_len))
		{
			fprintf(stderr, "verify error (5)\n");
			exit(EXIT_FAILURE);
		}
		sha1_update(&sc, sig, sig_len);

		printf(".");
		fflush(stdout);
	}

	xfree(priv);
	xfree(priv_dec);
	xfree(pub);
	xfree(sig);
	xfree(tmp);
	xfree(s1_and_salt);
	xfree(q00_q01_hpk);

	uint8_t hv1[20], hv2[20];
	HEXTOBIN(hv1, ref_hv);
	sha1_out(&sc, hv2);
	check_eq(hv1, hv2, 20, "aggregate hash");
#ifdef OUT_SIGS
	fclose(fd);
#endif

	printf("\n");
	fflush(stdout);
}

int
main(void)
{
	test_shake();
	test_shake_x4();

	test_multiple_sigs(8, 100, "d05fbd38bb376ebc30ed32c5752129a66b7bd443");
	test_multiple_sigs(9, 100, "cd0c0bd8dc16ccccda4a19a7a1394d089036030d");
	test_multiple_sigs(10, 100, "5537795eeec59376a1710fa4ec9e38d582bd0b68");

	printf("degree      priv     pub     sig\n");
	for (unsigned logn = 8; logn <= 10; logn ++) {
		printf("n = %4u   %5u   %5u   %5u\n",
			1u << logn,
			HAWK_PRIVKEY_SIZE(logn),
			HAWK_PUBKEY_SIZE(logn),
			HAWK_SIG_SIZE(logn));
	}
	fflush(stdout);
	return 0;
}
