/*
 * By Steve Reid <sreid@sea-to-sky.net>
 * 100% Public Domain
 * -----------------
 * Modified 7/98
 * By James H. Brown <jbrown@burgoyne.com>
 * Still 100% Public Domain
 * Corrected a problem which generated improper hash values on 16 bit machines
 * Routine SHA1Update changed from
 * void SHA1Update(SHA1_CTX* context, unsigned char* data, unsigned int len)
 * to
 * void SHA1Update(SHA1_CTX* context, unsigned char* data, unsigned long len)
 * The 'len' parameter was declared an int which works fine on 32 bit machines.
 * However, on 16 bit machines an int is too small for the shifts being done
 * against it. This caused the hash function to generate incorrect values if
 * len was greater than 8191 (8K - 1) due to the 'len << 3' on line 3 of
 * SHA1Update().
 * Since the file IO in main() reads 16K at a time, any file 8K or larger would
 * be guaranteed to generate the wrong hash (e.g. Test Vector #3, a million
 * "a"s).
 * I also changed the declaration of variables i & j in SHA1Update to unsigned
 * long from unsigned int for the same reason.
 * These changes should make no difference to any 32 bit implementations since
 * an int and a long are the same size in those environments.
 * --
 * I also corrected a few compiler warnings generated by Borland C.
 * 1. Added #include <process.h> for exit() prototype
 * 2. Removed unused variable 'j' in SHA1Final
 * 3. Changed exit(0) to return(0) at end of main
 * ALL changes I made can be located by searching for comments containing 'JHB'
 * -----------------
 * Modified 8/98
 * By Steve Reid <sreid@sea-to-sky.net>
 * Still 100% public domain
 * 1- Removed #include <process.h> and used return() instead of exit()
 * 2- Fixed overwriting of finalcount in SHA1Final() (discovered by Chris Hall)
 * 3- Changed email address from steve@edmweb.com to sreid@sea-to-sky.net
 * -----------------
 * Modified 4/01
 * By Saul Kravitz <Saul.Kravitz@celera.com>
 * Still 100% PD
 * Modified to run on Compaq Alpha hardware.
 * ----------------
 * Modified 07/2002
 * By Ralph Giles <giles@artofcode.com>
 * Still 100% public domain
 * modified for use with stdint types, autoconf
 * code cleanup, removed attribution comments
 * switched SHA1Final() argument order for consistency
 * use SHA1_ prefix for public api
 * move public api to sha1.h
 */

#include "crypto.h"
#include <string.h>

#define rol(value, bits) (((value) << (bits)) | ((value) >> (32 - (bits))))
// blk0() and blk() perform the initial expand.
// I got the idea of expanding during the round function from SSLeay
// FIXME: can we do this in an endian-proof way?
#define blk0(i) (block->l[i] = (rol(block->l[i],24)&0xff00ff00) \
		 |(rol(block->l[i],8)&0x00ff00ff))
#define blk(i) (block->l[i&15] = rol(block->l[(i+13)&15]^block->l[(i+8)&15] \
				     ^block->l[(i+2)&15]^block->l[i&15],1))
// (R0+R1), R2, R3, R4 are the different operations used in SHA1
#define R0(v,w,x,y,z,i) \
	z+=((w&(x^y))^y)+blk0(i)+0x5a827999+rol(v,5);w=rol(w,30);
#define R1(v,w,x,y,z,i) \
	z+=((w&(x^y))^y)+blk(i)+0x5a827999+rol(v,5);w=rol(w,30);
#define R2(v,w,x,y,z,i) \
	z+=(w^x^y)+blk(i)+0x6ed9eba1+rol(v,5);w=rol(w,30);
#define R3(v,w,x,y,z,i) \
	z+=(((w|x)&y)|(w&x))+blk(i)+0x8f1bbcdc+rol(v,5);w=rol(w,30);
#define R4(v,w,x,y,z,i) \
	z+=(w^x^y)+blk(i)+0xca62c1d6+rol(v,5);w=rol(w,30);

void secure_wipe(uint8_t *data, size_t len)
{
	volatile uint8_t *p = data;
	while (len-- > 0) *p = 0;
}

static void sha1_transform(uint32_t state[5], const uint8_t buffer[64])
{
	uint32_t a, b, c, d, e;
	typedef union {
		uint8_t c[64];
		uint32_t l[16];
	} CHAR64LONG16;
	CHAR64LONG16* block;

	CHAR64LONG16 workspace;
	block = &workspace;
	memcpy(block, buffer, 64);

	// Copy context->state[] to working vars
	a = state[0];
	b = state[1];
	c = state[2];
	d = state[3];
	e = state[4];

	// 4 rounds of 20 operations each. Loop unrolled.
	R0(a,b,c,d,e, 0); R0(e,a,b,c,d, 1); R0(d,e,a,b,c, 2);R0(c,d,e,a,b, 3);
	R0(b,c,d,e,a, 4); R0(a,b,c,d,e, 5); R0(e,a,b,c,d, 6);R0(d,e,a,b,c, 7);
	R0(c,d,e,a,b, 8); R0(b,c,d,e,a, 9); R0(a,b,c,d,e,10);R0(e,a,b,c,d,11);
	R0(d,e,a,b,c,12); R0(c,d,e,a,b,13); R0(b,c,d,e,a,14);R0(a,b,c,d,e,15);
	R1(e,a,b,c,d,16); R1(d,e,a,b,c,17); R1(c,d,e,a,b,18);R1(b,c,d,e,a,19);
	R2(a,b,c,d,e,20); R2(e,a,b,c,d,21); R2(d,e,a,b,c,22);R2(c,d,e,a,b,23);
	R2(b,c,d,e,a,24); R2(a,b,c,d,e,25); R2(e,a,b,c,d,26);R2(d,e,a,b,c,27);
	R2(c,d,e,a,b,28); R2(b,c,d,e,a,29); R2(a,b,c,d,e,30);R2(e,a,b,c,d,31);
	R2(d,e,a,b,c,32); R2(c,d,e,a,b,33); R2(b,c,d,e,a,34);R2(a,b,c,d,e,35);
	R2(e,a,b,c,d,36); R2(d,e,a,b,c,37); R2(c,d,e,a,b,38);R2(b,c,d,e,a,39);
	R3(a,b,c,d,e,40); R3(e,a,b,c,d,41); R3(d,e,a,b,c,42);R3(c,d,e,a,b,43);
	R3(b,c,d,e,a,44); R3(a,b,c,d,e,45); R3(e,a,b,c,d,46);R3(d,e,a,b,c,47);
	R3(c,d,e,a,b,48); R3(b,c,d,e,a,49); R3(a,b,c,d,e,50);R3(e,a,b,c,d,51);
	R3(d,e,a,b,c,52); R3(c,d,e,a,b,53); R3(b,c,d,e,a,54);R3(a,b,c,d,e,55);
	R3(e,a,b,c,d,56); R3(d,e,a,b,c,57); R3(c,d,e,a,b,58);R3(b,c,d,e,a,59);
	R4(a,b,c,d,e,60); R4(e,a,b,c,d,61); R4(d,e,a,b,c,62);R4(c,d,e,a,b,63);
	R4(b,c,d,e,a,64); R4(a,b,c,d,e,65); R4(e,a,b,c,d,66);R4(d,e,a,b,c,67);
	R4(c,d,e,a,b,68); R4(b,c,d,e,a,69); R4(a,b,c,d,e,70);R4(e,a,b,c,d,71);
	R4(d,e,a,b,c,72); R4(c,d,e,a,b,73); R4(b,c,d,e,a,74);R4(a,b,c,d,e,75);
	R4(e,a,b,c,d,76); R4(d,e,a,b,c,77); R4(c,d,e,a,b,78);R4(b,c,d,e,a,79);

	// Add the working vars back into context.state[]
	state[0] += a;
	state[1] += b;
	state[2] += c;
	state[3] += d;
	state[4] += e;

	secure_wipe((uint8_t*)&a, sizeof(a));
	secure_wipe((uint8_t*)&b, sizeof(b));
	secure_wipe((uint8_t*)&c, sizeof(c));
	secure_wipe((uint8_t*)&d, sizeof(d));
	secure_wipe((uint8_t*)&e, sizeof(e));
}

void sha1_init(sha1_ctx_t *context)
{
	context->state[0] = 0x67452301;
	context->state[1] = 0xefcdab89;
	context->state[2] = 0x98badcfe;
	context->state[3] = 0x10325476;
	context->state[4] = 0xc3d2e1f0;
	context->count[0] = context->count[1] = 0;
}

void sha1_update(sha1_ctx_t *ctx, const uint8_t *in, size_t in_len)
{
	size_t i;
	size_t j = (ctx->count[0] >> 3) & 63;
	if ((ctx->count[0] += (uint32_t)(in_len << 3)) < (in_len << 3))
		ctx->count[1]++;
	ctx->count[1] += (uint32_t)(in_len >> 29);
	if ((j + in_len) > 63) {
		memcpy(&ctx->buffer[j], in, (i = 64-j));
		sha1_transform(ctx->state, ctx->buffer);
		for (; i+63 < in_len; i += 64)
			sha1_transform(ctx->state, in + i);
		j = 0;
	}
	else i = 0;
	memcpy(&ctx->buffer[j], &in[i], in_len - i);
}

void sha1_final(sha1_ctx_t *ctx, uint8_t out[SHA1_DIGEST_SIZE])
{
	uint8_t finalcount[8] = {0};
	for (int i = 0; i < 8; i++)
		finalcount[i] = (uint8_t)((ctx->count[(i >= 4 ? 0 : 1)] >> ((3-(i & 3)) * 8) ) & 255);
	sha1_update(ctx, (uint8_t *)"\200", 1);
	while ((ctx->count[0] & 504) != 448)
		sha1_update(ctx, (uint8_t *)"\0", 1);
	sha1_update(ctx, finalcount, 8); // Should cause SHA1_Transform
	for (int i = 0; i < SHA1_DIGEST_SIZE; i++)
		out[i] = (uint8_t)((ctx->state[i>>2] >> ((3-(i & 3)) * 8) ) & 255);

	// Make SHA1Transform overwrite its own static vars
	sha1_transform(ctx->state, ctx->buffer);

	secure_wipe((uint8_t*)&ctx->buffer, sizeof(ctx->buffer));
	secure_wipe((uint8_t*)&ctx->state, sizeof(ctx->state));
	secure_wipe((uint8_t*)&ctx->count, sizeof(ctx->count));
	secure_wipe((uint8_t*)&finalcount, sizeof(finalcount));
}

void sha1(const uint8_t *in, size_t in_len, uint8_t out[SHA1_DIGEST_SIZE])
{
	sha1_ctx_t ctx;
	sha1_init(&ctx);
	sha1_update(&ctx, in, in_len);
	sha1_final(&ctx, out);
}

void hmac_sha1(const uint8_t *in, size_t in_len, const uint8_t *key,
               size_t key_len, uint8_t *out)
{
	sha1_ctx_t ictx;
	sha1_ctx_t octx;
	uint8_t inner_hash[SHA1_DIGEST_SIZE] = {0};
	uint8_t key_hash[SHA1_DIGEST_SIZE] = {0};
	uint8_t block[SHA1_BLOCK_SIZE] = {0};

	// Use a digest of the key if it's larger than a block
	if (key_len > SHA1_BLOCK_SIZE) {
		sha1(key, key_len, key_hash);
		key = key_hash;
		key_len = SHA1_DIGEST_SIZE;
	}

	// Inner digest with a padded version of the key
	sha1_init(&ictx);
	for (size_t i = 0; i < key_len; i++)
		block[i] = key[i] ^ 0x36;
	for (size_t i = key_len; i < SHA1_BLOCK_SIZE; i++)
		block[i] = 0x36;
	sha1_update(&ictx, block, SHA1_BLOCK_SIZE);
	sha1_update(&ictx, in, in_len);
	sha1_final(&ictx, inner_hash);

	// Outer digest with another padded version of the key
	sha1_init(&octx);
	for (size_t i = 0; i < key_len; i++)
		block[i] = key[i] ^ 0x5c;
	for (size_t i = key_len; i < SHA1_BLOCK_SIZE; i++)
		block[i] = 0x5c;
	sha1_update(&octx, block, SHA1_BLOCK_SIZE);
	sha1_update(&octx, inner_hash, SHA1_DIGEST_SIZE);
	sha1_final(&octx, out);

	secure_wipe(inner_hash, sizeof(inner_hash));
	secure_wipe(key_hash, sizeof(key_hash));
	secure_wipe(block, sizeof(block));
}