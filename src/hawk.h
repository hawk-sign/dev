#ifndef HAWK_H__
#define HAWK_H__

#include <stddef.h>
#include <stdint.h>

#include "sha3.h"

/*
 * All sizes below are in bytes.
 *
 * Private keys have an inherently fixed size: they contain the seed used
 * to (re)generate (f,g), the polynomials F mod 2 and G mod 2 (n bits = n/8
 * bytes each), and a hash of the public key. The seed length is 16, 24 or
 * 40 bytes, for n = 256, 512 or 1024. The public key hash uses SHAKE256
 * with an output of the same size as the seed.
 *
 * Internally, public keys and signatures have varying sizes. We pad them
 * with zeros to a fixed length (padding bytes are verified to be zero upon
 * decoding); keygen and sign enforce the lengths by restarting in case the
 * obtained result does not fit. The fixed sizes are set so that such
 * restarts are rare enough that their practical impact on average
 * performance is negligible.
 *
 * Measured average sizes and standard deviations (over 10000 key pairs and
 * 1000 signatures per key pair):
 *   degree (n)         public key          signature
 *       256          444.07 (1.902)      243.98 (0.916)
 *       512         1015.93 (6.353)      536.55 (3.691)
 *      1024         2404.44 (17.274)    1193.12 (5.588)
 *
 * We enforce a maximum size on public keys. If the obtained public key is
 * larger than this size, we discard the key pair and generate a new one.
 * The maximum size is chosen such that retries do not occur frequently and
 * key generation is not slowed down by the retries.
 *
 * Similarly, signatures also have a maximum size. If a generated signature
 * is too large, signing is restarted with a different salt. The maximum
 * size is chosen as 5 standard deviations above the average. A retry
 * happens less than once in a million.
 *
 *   degree (n)    private key    public key    signature
 *       256            96            450           249
 *       512           184           1024           555
 *      1024           360           2440          1221
 */

/*
 * Private key length (in bytes).
 */
#define HAWK_PRIVKEY_SIZE(logn) \
	(8u + (11u << ((logn) - 5)))

/*
 * Public key length (in bytes).
 */
#define HAWK_PUBKEY_SIZE(logn)   (450u \
	+ 574u * (2u >> (10 - (logn))) + 842u * ((1u >> (10 - (logn)))))

/*
 * Signature length (in bytes).
 */
#define HAWK_SIG_SIZE(logn)      (249u \
	+ 306u * (2u >> (10 - (logn))) + 360u * ((1u >> (10 - (logn)))))

/*
 * Temporary buffer size for key pair generation.
 */
#define HAWK_TMPSIZE_KEYGEN(logn)         ((26u << (logn)) + 7)

/*
 * Temporary buffer size for signature generation.
 */
#define HAWK_TMPSIZE_SIGN(logn)           ((6u << (logn)) + 7)

/*
 * Temporary buffer size for signature verification (minimum supported size).
 */
#define HAWK_TMPSIZE_VERIFY(logn)         ((10u << (logn)) + 7)

/*
 * Temporary buffer size for slightly faster signature verification. Using
 * this buffer size yields the same verification performance as decoding
 * the signature and public key first, then calling the verification
 * function.
 */
#define HAWK_TMPSIZE_VERIFY_FAST(logn) \
	((15u << (logn)) + 64 + 64u * (1u >> (10 - (logn))) + 7)

/*
 * Type for a random source (with a context structure).
 * The RNG is invoked with a destination buffer 'dst' of size 'len' bytes.
 * It should fill it with random bytes. The RNG uses the context pointer
 * ('ctx') in any way it sees fit.
 */
typedef void (*hawk_rng)(void *ctx, void *dst, size_t len);

/*
 * Generate a new public/private key pair.
 *
 * Degree logarithm is provided as logn (8, 9 or 10). The private key
 * is written into 'priv' (size HAWK_PRIVKEY_SIZE(logn), exactly), while
 * the public key is written into 'pub' (size HAWK_PUBKEY_SIZE(logn),
 * exactly).
 *
 * The private and public key are also copied, in that order, in the tmp
 * buffer. The priv and/or pub parameters may be set to NULL, in which
 * case the caller will have to retrieve the corresponding values from the
 * tmp buffer afterwards.
 *
 * On error, 0 is returned. An error is reported if logn is not a
 * supported value, of if the temporary buffer is too short. On success,
 * 1 is returned.
 *
 * The temporary buffer is provided as tmp, with size tmp_len bytes.
 * In all generality, providing at least 26*(2^logn) + 7 bytes is always
 * sufficient (this is the value returned by HAWK_TMPSIZE_KEYGEN).
 * If tmp is 8-byte aligned, then 26*(2^logn) bytes are enough.
 */
int
hawk_keygen(unsigned logn, void *priv, void *pub,
	hawk_rng rng, void *rng_context, void *tmp, size_t tmp_len);

/*
 * Start a signature process by initializing the provided SHAKE context.
 * This is equivalent to calling shake_init(sc_data, 256). The caller
 * should then inject the message data into the context, using the
 * SHAKE API (shake_inject() function). The same function works for both
 * signature generation and verification.
 */
void hawk_sign_start(shake_context *sc_data);
#define hawk_verify_start   hawk_sign_start

/*
 * Generate an Hawk signature.
 *    logn          log of degree (8 to 10, for n = 256 to 1024)
 *    rng           random source to use for sampling
 *    rng_context   context for the random source
 *    sig           signature output buffer (may be NULL)
 *    sc_data       SHAKE256 context with message injected (_not_ flipped)
 *    priv          private key (encoded)
 *    tmp           temporary buffer
 *    tmp_len       temporary buffer length (in bytes)
 *
 * Returned value is 1 on success, 0 on error. An error is returned if
 * logn is unsupported (not in the 8 to 10 range) or if the temporary
 * buffer is too short.
 *
 * The signature is always returned in the tmp buffer. If the sig
 * parameter is not NULL, then the signature is also written in that
 * buffer. The signature length is HAWK_SIG_SIZE(logn).
 *
 * sc_data contains the SHAKE256 context with the message injected. It
 * MUST NOT have been flipped to extraction state. sc_data is unmodified
 * by this function.
 *
 * Minimum temporary buffer size: 6*2^logn + 7 bytes
 * (This is the size returned by HAWK_TMPSIZE_SIGN(logn).)
 */
int hawk_sign_finish(unsigned logn,
	hawk_rng rng, void *rng_context,
	void *sig, const shake_context *sc_data,
	const void *priv, void *tmp, size_t tmp_len);

/*
 * A variant of hawk_sign_finish(), with two changes:
 *
 *   - The provided random source is used directly, instead of being
 *     used to initialize some internal SHAKE instances.
 *
 *   - The private key may be provided in a pre-decoded format, with the
 *     polynomials f (n bytes), g (n bytes), F mod 2 (n bits = n/8 bytes)
 *     and G mod 2 (n bits = n/8 bytes), in that order. The
 *     hawk_decode_private_key() function can perform that decoding step.
 *     The private key can also be provided in encoded format; the
 *     priv_len parameter specifies the length (in bytes) of the key.
 *
 * The produced signatures are not identical to the ones generated with
 * hawk_sign_finish(), but they are fully interoperable. This function is
 * intended to support hardware platforms for which the cost of SHAKE is
 * high, but a different and fast RNG is available (e.g. leveraging
 * AES hardware). In that mode, the provided RNG is always invokved with
 * an output length of
 */
int hawk_sign_finish_alt(unsigned logn,
	hawk_rng rng, void *rng_context,
	void *sig, const shake_context *sc_data,
	const void *priv, size_t priv_len, void *tmp, size_t tmp_len);

/*
 * Decode the private key. The input private key (priv) has size
 * exactly HAWK_PRIVKEY_SIZE(logn) bytes; the output decoded key (priv_dec)
 * contains the f, g, F mod 2 and G mod 2 polynomials, in that order,
 * for a total size of 2.25*2^logn bytes (n bytes for each of f and g,
 * n/8 bytes for each of F mod 2 and G mod 2). The decoded private key
 * can be used with the hawk_sign_finish_alt() function.
 */
void hawk_decode_private_key(unsigned logn, void *priv_dec, const void *priv);

/*
 * Decoded private key length (in bytes). Decoded private keys can be used
 * with hawk_sign_finish_alt(). A decoded private key contains the f, g,
 * F mod 2 and G mod 2 polynomials, and public key hash, in that order (f
 * and g use n bytes each, F mod 2 and G mod 2 use n bits = n/8 bytes each).
 */
#define HAWK_PRIVKEY_DECODED_SIZE(logn) \
	(37u << ((logn) - 4))

/*
 * Decode a signature value. The encoded signature is provided in sig,
 * with size sig_len. If the length is not exactly HAWK_SIG_SIZE(logn)
 * bytes, then an error is reported.
 *
 * The signature polynomial s1 (int16_t[n]) and the salt (14, 24 or 40
 * bytes) are written into s1_and_salt, in that order. The
 * HAWK_DECODED_SIG_LENGTH() macro yields the number of produced 16-bit
 * values, for a given degree.
 *
 * Returned value is 1 on success, 0 on error.
 *
 * Note: this function does _not_ verify the sym-break condition; this is
 * done within hawk_verify(). However, it checks that all elements of s1
 * are within the allowed range.
 */
int hawk_decode_signature(unsigned logn,
	int16_t *s1_and_salt, const void *sig, size_t sig_len);

/*
 * Get the number of 16-bit elements for a decoded signature in RAM.
 */
#define HAWK_DECODED_SIG_LENGTH(logn)   ((1u << (logn)) + 7u \
	+ 5u * (2u >> (10 - (logn))) + 3u * (1u >> (10 - (logn))))

/*
 * Decode a public key. The encoded public key is provided in pub,
 * with size pub_len. If the length is not exactly HAWK_PUBKEY_SIZE(logn)
 * bytes, then an error is reported.
 *
 * The decoded polynomials q00 (n/2 elements) and q01 (n elements) are
 * written into q00_q01_hpk, in that order, followed by the hash of the
 * public key. The total output size (expressed in 16-bit units) can
 * be obtained from HAWK_DECODED_PUB_LENGTH.
 *
 * Returned value is 1 on success, 0 on error.
 *
 * Note: this function checks that all elements of q00 and q01 are within
 * the respective allowed ranges.
 */
int hawk_decode_public_key(unsigned logn,
	int16_t *q00_q01_hpk, const void *pub, size_t pub_len);

/*
 * Get the number of 16-bit elements for a decode public key in RAM.
 */
#define HAWK_DECODED_PUB_LENGTH(logn) \
	((3u << ((logn) - 1)) + (1u << ((logn) - 5)))

/*
 * Verify an Hawk signature.
 *    logn          log of degree (8 to 10, for n = 256 to 1024)
 *    sig           signature (encoded or decoded)
 *    sig_len       signature length, or (size_t)-1 for a decoded signature
 *    sc_data       SHAKE256 context with message injected (_not_ flipped)
 *    pub           public key (encoded or decoded)
 *    pub_len       public key length, or (size_t)-1 for a decoded public key
 *    tmp           temporary buffer
 *    tmp_len       temporary buffer length (in bytes)
 *
 * If sig_len is equal to -1 (cast to size_t), then the sig parameter
 * should point at the decoded signature, as obtained by calling
 * hawk_decode_signature(). Otherwise, sig should contain the encoded
 * signature, of length exactly sig_len bytes. This function checks that,
 * in the latter case, the length is equal to HAWK_SIG_SIZE(logn).
 *
 * If pub_len is equal to -1 (cast to size_t), then the pub parameter
 * should point at the decoded public key, as obtained by calling
 * hawk_decode_public_key(). Otherwise, pub should contain the encoded
 * public key, of length exactly pub_len bytes. This function checks that,
 * in the latter case, the length is equal to HAWK_PUBKEY_SIZE(logn).
 *
 * Returned value is 1 on success (signature matches the provided public key
 * and hashed message), 0 on failure.
 *
 * Minimum temporary buffer size: 10*2^logn + 7 bytes
 * (This is the size returned by HAWK_TMPSIZE_VERIFY(logn).)
 * If the temporary buffer is larger, then this function may use the extra
 * space to store the decoded version of the public key and/or the signature,
 * which slightly speeds up the process. HAWK_TMPSIZE_VERIFY_FAST(logn) is
 * the buffer size that provides the fastest processing.
 */
int hawk_verify_finish(unsigned logn,
	const void *sig, size_t sig_len,
	const shake_context *sc_data,
	const void *pub, size_t pub_len,
	void *tmp, size_t tmp_len);

#endif
