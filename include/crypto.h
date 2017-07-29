#include <stdint.h>
#include <stddef.h>

#define SHA1_DIGEST_SIZE 20
#define SHA1_BLOCK_SIZE 64

typedef struct {
	uint32_t state[5];
	uint32_t count[2];
	uint8_t  buffer[64];
} sha1_ctx_t;

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
extern void sha1_final(sha1_ctx_t *ctx, uint8_t out[SHA1_DIGEST_SIZE]);

/**
 * Digests the given input buffer and directly writes the result to the output
 * buffer (which should be SHA1_DIGEST_SIZE bytes long at least).
 */
extern void sha1(const uint8_t *in, size_t in_len, uint8_t out[SHA1_DIGEST_SIZE]);

/**
 * Computes the HMAC-SHA1 of the given input buffer using a given key, then
 * writes the result to the output buffer (which must be at least
 * SHA1_DIGEST_LENGTH-byte long).
 */
extern void hmac_sha1(const uint8_t *in, size_t in_len, const uint8_t *key, size_t key_len, uint8_t *out);
