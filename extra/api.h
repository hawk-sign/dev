#ifndef api_h
#define api_h

/* Private key size (bytes) */
#define CRYPTO_SECRETKEYBYTES   zzzSECRETKEYBYTES

/* Public key size (bytes) */
#define CRYPTO_PUBLICKEYBYTES   zzzPUBLICKEYBYTES

/* Signature size (bytes) */
#define CRYPTO_BYTES            zzzCRYPTOBYTES

/* Algorithm name */
#define CRYPTO_ALGNAME          "Hawk-zzzN"

/*
 * Generate a new key pair. The public and private key have sizes
 * CRYPTO_PUBLICKEYBYTES and CRYPTO_SECRETKEYBYTES, respectively,
 * and are written in the provided pk and sk buffers, respectively.
 *
 * Returned value is 0 on success, -1 on error.
 */
int crypto_sign_keypair(unsigned char *pk, unsigned char *sk);

/*
 * Sign a message. Source message is found in buffer m[], of size
 * mlen bytes. A wrapped object that includes both the source message
 * and the signature is written into sm[], and its length is written
 * in *smlen. The output size (*smlen) is at most mlen + CRYPTO_BYTES.
 * The private key is provided as pointer sk.
 *
 * Buffers m[] and sm[] may overlap freely.
 *
 * Returned value is 0 on success, -1 on error.
 */
int crypto_sign(unsigned char *sm, unsigned long long *smlen,
	const unsigned char *m, unsigned long long mlen,
	const unsigned char *sk);

/*
 * Verify a signed message. A wrapped object (as produced by crypto_sign())
 * is expected in sm[], with length smlen bytes. If the signature is valid,
 * then the message itself is extracted and written into m[], with its size
 * written into *mlen (necessarily less than smlen). The public key is
 * obtained from pk[].
 *
 * Buffers m[] and sm[] may overlap freely.
 *
 * Returned value is 0 on success, -1 on error.
 */
int crypto_sign_open(unsigned char *m, unsigned long long *mlen,
	const unsigned char *sm, unsigned long long smlen,
	const unsigned char *pk);

#endif /* api_h */
