#include <stdint.h>
#include <stddef.h>

#define SHA1_DIGEST_SIZE 20
#define SHA1_BLOCK_SIZE 64

typedef struct {
	uint32_t state[5];
	uint32_t count[2];
	uint8_t  buffer[64];
} sha1_ctx_t;

typedef struct __attribute__((__packed__)) {
	uint8_t hash[SHA1_DIGEST_SIZE];
} sha1_digest_t;

/**
 * Initialises a cryptographically secure pseudo-random number generator,
 * possibly using the given bytes as an additional entropy source.
 */
extern void init_local_random_generator(const uint8_t *in, size_t in_len);

/**
 * Writes a string of cryptographically securely generated random bytes,
 * derived from an entropy pool not accessible from the TPM. This is useful
 * when generating nonces later sent as challenges sent to the TPM, so that it
 * cannot predict or force their value.
 * When first called, it may use the given buffer to initialise (or "stir")
 * its backing entropy pool, as an additional entropy source for good measure.
 */
extern void get_local_random_bytes(uint8_t *out, size_t out_len);

/*
 * Securely dispose of sensitive data in RAM. memset() can be optimised-out by some compilers,
 * see cert.org MSC06-C
 */
extern void secure_wipe(uint8_t *data, size_t len);

/**
 * Initialize a new SHA1 digest context
 */
extern void sha1_init(sha1_ctx_t *ctx);

/**
 * Digest one more chunk of data, can be called multiple times
 */
extern void sha1_update(sha1_ctx_t *ctx, const uint8_t *in, size_t in_len);

/**
 * Add padding and return the entire message digest
 */
extern void sha1_final(sha1_ctx_t *ctx, sha1_digest_t *out);

/**
 * Digests the given input buffer and directly writes the result to the output
 * buffer (which should be SHA1_DIGEST_SIZE bytes long at least).
 */
extern void sha1(const uint8_t *in, size_t in_len, sha1_digest_t *out);

/**
 * Computes the HMAC-SHA1 of the given input buffer using a given key, then
 * writes the result to the output buffer (which must be at least
 * SHA1_DIGEST_LENGTH-byte long).
 */
extern void hmac_sha1(const uint8_t *in, size_t in_len, const uint8_t *key, size_t key_len, sha1_digest_t *out);
