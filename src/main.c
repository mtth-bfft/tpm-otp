#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>

#ifdef DEBUG
#define DEBUG_INFO(...) fprintf(stderr, " [+] " __VA_ARGS__)
#define DEBUG_WARN(...) fprintf(stderr, " [!] " __VA_ARGS__)
#define DEBUG_HEXDUMP(blob, len) do { \
	fprintf(stderr, " [+] %zu bytes:\n", (size_t)len); \
	for (size_t z = 0; z < len; z ++) { \
		fprintf(stderr, " %02X", *(((uint8_t*)blob)+z)); \
	} \
	fprintf(stderr, "\n"); \
} while(0)
#else
#define DEBUG_INFO(...)
#define DEBUG_WARN(...)
#define DEBUG_HEXDUMP(blob, len)
#endif

#define MAX_PATH_LEN 255
#define MAX_INT 0xFFFFFFFF

// Constants from TPM v1.2 specifications
#define TPM_TAG_RQU_COMMAND ((uint16_t)(0x00C1))
#define TPM_TAG_RQU_AUTH1_COMMAND ((uint16_t)(0x00C2))
#define TPM_TAG_RSP_COMMAND (uint16_t)(0x00C4)
#define TPM_ORD_GetRandom ((uint32_t)0x46)
#define TPM_ORD_NV_ReadValue ((uint32_t)0xCF)
#define TPM_E_BADINDEX 0x00000002
#define TPM_E_WRONGPCRVAL 0x00000018
#define TPM_E_AUTH_CONFLICT 0x0000003B
#define TPM_HEADER_SIZE (sizeof(tpm_header_t))
#define SHA1_DIGEST_SIZE 14 // 160 bits

typedef struct {
	int chardev_fd;
	char chardev_path[MAX_PATH_LEN];
} tpm_context_t;

typedef struct __attribute__((__packed__)) {
	uint16_t tag;
	uint32_t payload_length;
	uint32_t code;
} tpm_header_t;

typedef struct __attribute__((__packed__)) {
	uint8_t hash[SHA1_DIGEST_SIZE];
} sha1_hash_t;

typedef struct __attribute__((__packed__)) {
	uint32_t auth_handle;
	sha1_hash_t nonce_local;
	sha1_hash_t nonce_tpm;
	int8_t continue_auth_session;
	sha1_hash_t hmac;
} tpm_oiap_auth_t;

static const char* tpm_chardev[] = {
	"/dev/tpm",
	"/dev/tpm0",
	"/udev/tpm0",
	NULL
};

static const char* local_rand_chardev[] = {
	"/dev/random",
	"/dev/urandom",
	NULL
};

int tpm_get_random_bytes(tpm_context_t *tpm, uint8_t *out, size_t out_len);

/**
 * Writes a string of cryptographically securely generated random bytes,
 * derived from an entropy pool not accessible from the TPM. This is useful
 * when generating nonces later sent as challenges sent to the TPM, so that it
 * cannot predict or force their value.
 * When first called, it may use the given buffer to initialise (or "stir")
 * its backing entropy pool, as an additional entropy source for good measure.
 */
void get_local_random_bytes(uint8_t *out, size_t out_len)
{
	static int rand_chardev = -1;
	if (rand_chardev < 0) {
		int try = 0;
		while(local_rand_chardev[try] != NULL) {
			rand_chardev = open(local_rand_chardev[try], O_RDWR);
			if (rand_chardev != -1)
				break;
		}
		if (local_rand_chardev[try] == NULL) {
			fprintf(stderr, "Error: no random number source available. Aborting.\n");
			exit(ENXIO);
		}
		write(rand_chardev, out, out_len);
	}
	ssize_t read_len;
	do {
		read_len = read(rand_chardev, out, out_len);
		if (read_len < 0) {
			fprintf(stderr, "Error: unable to read from random number source (%s)\n",
				strerror(errno));
			exit(errno);
		}
		out_len -= read_len;
		out += read_len;
	} while(read_len > 0);
}

/**
 * Prints an error message if something unexpected prevents opening the
 * given character device and returns -1, otherwise returns 0.
 */
int tpm_open(const char *path, tpm_context_t *tpm)
{
	tpm->chardev_fd = open(path, O_RDWR | O_SYNC);
	if (tpm->chardev_fd == -1) {
		if (errno == ENOENT)
			return errno;
		const char *hint = "";
		if (errno == EACCES)
			hint = ", am I running as root?";
		else if (errno == EBUSY)
			hint = ", is tcsd running too?";
		fprintf(stderr, "Error: cannot access TPM device %s (%s%s)\n",
			path, strerror(errno), hint);
		return errno;
	}
	strncpy(tpm->chardev_path, path, sizeof(tpm->chardev_path));
	// Stir the local entropy pool thanks to the TPM's one, in case we're
	// running low during boot
	uint8_t tpm_entropy[255] = {0};
	int res = tpm_get_random_bytes(tpm, tpm_entropy, sizeof(tpm_entropy));
	if (res != 0)
		DEBUG_WARN("Unable to stir local entropy pool: error %d\n", res);
	get_local_random_bytes(tpm_entropy, sizeof(tpm_entropy));
	//TODO: Stir the TPM's entropy pool thanks to the local one
	return 0;
}

/**
 * Releases all allocated resources associated with the given TPM context.
 */
int tpm_close(tpm_context_t *tpm)
{
	int res = 0;
	if (tpm->chardev_fd > 0)
		res = close(tpm->chardev_fd);
	return res;
}

/**
 * Serialize most-significant-byte-first the given 32-bit unsigned integer
 * in the given buffer. Returns the number of bytes used.
 */
size_t serialize_uint32(uint8_t *blob, size_t offset, uint32_t in)
{
	blob[offset++] = (uint8_t)((in >> 24) & 0xFF);
	blob[offset++] = (uint8_t)((in >> 16) & 0xFF);
	blob[offset++] = (uint8_t)((in >>  8) & 0xFF);
	blob[offset++] = (uint8_t)(in & 0xFF);
	return 4;
}

/**
 * Serialize most-significant-byte-first the given 16-bit unsigned integer
 * in the given buffer. Returns the number of bytes used.
 */
size_t serialize_uint16(uint8_t *blob, size_t offset, uint16_t in)
{
	blob[offset++] = (uint8_t)((in >>  8) & 0xFF);
	blob[offset++] = (uint8_t)(in & 0xFF);
	return 2;
}

uint32_t deserialize_uint32(uint8_t *blob)
{
	return ((blob[0] << 24) | (blob[1] << 16) | (blob[2] << 8) | blob[3]);
}

uint16_t deserialize_uint16(uint8_t *blob)
{
	return ((blob[0] << 8) | blob[1]);
}

/**
 * Ask the TPM for cryptographically securely generated random bytes.
 * This function may block for some time, since multiple requests might be
 * necessary to get the requested number of bytes (some TPMs give ~100 bytes
 * at a time).
 */
int tpm_get_random_bytes(tpm_context_t *tpm, uint8_t *out, size_t out_len)
{
	if (out == NULL || out_len > MAX_INT)
		return -EINVAL;
	int res = 0;
	uint8_t *buf = malloc(TPM_HEADER_SIZE + sizeof(uint32_t) + out_len);
	if (buf == NULL)
		return ENOMEM;
	while (out_len > 0) {
		// Header
		uint64_t req_len = 0;
		req_len += serialize_uint16(buf, req_len, TPM_TAG_RQU_COMMAND);
		req_len += serialize_uint32(buf, req_len, TPM_HEADER_SIZE + sizeof(uint32_t));
		req_len += serialize_uint32(buf, req_len, TPM_ORD_GetRandom);
		// Params
		req_len += serialize_uint32(buf, req_len, (uint32_t)out_len);
		DEBUG_HEXDUMP(buf, req_len);
		size_t req_sent = write(tpm->chardev_fd, buf, req_len);
		if (req_sent != req_len) {
			fprintf(stderr, "Error: truncated write to TPM device (%s)\n",
				strerror(errno));
			res = errno;
			goto cleanup;
		}
		size_t read_len = read(tpm->chardev_fd, buf, TPM_HEADER_SIZE + sizeof(uint32_t) + out_len);
		DEBUG_HEXDUMP(buf, read_len);
		if (read_len < TPM_HEADER_SIZE) {
			fprintf(stderr, "Error: truncated read from TPM (%zu bytes)\n", read_len);
			res = EINVAL;
			goto cleanup;
		}
		uint16_t resp_tag = deserialize_uint16(buf);
		uint32_t resp_len = deserialize_uint32(&buf[2]);
		uint32_t resp_code = deserialize_uint32(&buf[6]);
		if (resp_tag != TPM_TAG_RSP_COMMAND) {
			fprintf(stderr, "Error: invalid response tag 0x%04X\n", resp_tag);
			res = EINVAL;
			goto cleanup;
		} else if (resp_code != 0) {
			DEBUG_WARN("TPM returned error code %u\n", resp_code);
			res = resp_code;
			goto cleanup;
		}
		uint32_t payload_len = deserialize_uint32(&buf[10]);
		if (resp_len != TPM_HEADER_SIZE + sizeof(uint32_t) + payload_len) {
			fprintf(stderr, "Error: malformed TPM response, invalid payload length\n");
			res = EINVAL;
			goto cleanup;
		} else if (payload_len > out_len) {
			DEBUG_WARN("TPM returned too much data (%u/%zu bytes)\n",
				payload_len, out_len);
			payload_len = out_len;
		}
		memcpy(out, buf + TPM_HEADER_SIZE + sizeof(uint32_t), payload_len);
		out += payload_len;
		out_len -= payload_len;
	}
cleanup:
	if (buf != NULL)
		free(buf);
	return res;
}

int tpm_auth_oiap(tpm_context_t *tpm, tpm_oiap_auth_t *auth, uint8_t req,
		size_t req_len, const sha1_hash_t *passwd_digest)
{
	get_local_random_bytes(auth->nonce_local, sizeof(auth->nonce_local));
	auth->continue_auth_session = 0;
	
}

int tpm_read_nvram(tpm_context_t *tpm, int addr, int offset, uint8_t *out,
                   size_t out_len, const sha1_hash_t *owner_passwd_digest)
{
	if (out == NULL || out_len > MAX_INT)
		return -EINVAL;
	int res = 0;
	uint8_t *buf = malloc(TPM_HEADER_SIZE + sizeof(uint32_t) + out_len);
	if (buf == NULL)
		return ENOMEM;
	uint32_t tag = TPM_TAG_RQU_COMMAND;
	tpm_oiap_auth_t auth;
	if (owner_passwd_digest != NULL) {
		tag = TPM_TAG_RQU_AUTH1_COMMAND;

	}
	while (out_len > 0) {
		// Header
		uint64_t req_len = 0;
		req_len += serialize_uint16(buf, req_len, tag);
		req_len += serialize_uint32(buf, req_len, TPM_HEADER_SIZE + sizeof(uint32_t)*3);
		req_len += serialize_uint32(buf, req_len, TPM_ORD_NV_ReadValue);
		// Params
		req_len += serialize_uint32(buf, req_len, (uint32_t)addr);
		req_len += serialize_uint32(buf, req_len, (uint32_t)offset);
		req_len += serialize_uint32(buf, req_len, (uint32_t)out_len);
		DEBUG_HEXDUMP(buf, req_len);
		size_t req_sent = write(tpm->chardev_fd, buf, req_len);
		if (req_sent != req_len) {
			fprintf(stderr, "Error: truncated write to TPM device (%s)\n",
				strerror(errno));
			res = errno;
			goto cleanup;
		}
		size_t read_len = read(tpm->chardev_fd, buf, TPM_HEADER_SIZE + sizeof(uint32_t) + out_len);
		DEBUG_HEXDUMP(buf, read_len);
		if (read_len < TPM_HEADER_SIZE) {
			fprintf(stderr, "Error: truncated read from TPM (%zu bytes)\n", read_len);
			res = EINVAL;
			goto cleanup;
		}
		uint16_t resp_tag = deserialize_uint16(buf);
		uint32_t resp_len = deserialize_uint32(&buf[2]);
		uint32_t resp_code = deserialize_uint32(&buf[6]);
		uint32_t payload_len = deserialize_uint32(&buf[10]);
		if (resp_tag != TPM_TAG_RSP_COMMAND) {
			fprintf(stderr, "Error: invalid response tag 0x%04X\n", resp_tag);
			res = EINVAL;
			goto cleanup;
		} else if (resp_code != 0) {
			DEBUG_WARN("TPM returned error code %u\n", resp_code);
			res = resp_code;
			goto cleanup;
		} else if (resp_len != TPM_HEADER_SIZE + sizeof(uint32_t) + payload_len) {
			fprintf(stderr, "Error: malformed response, invalid payload length\n");
			res = EINVAL;
			goto cleanup;
		} else if (payload_len > out_len) {
			DEBUG_WARN("TPM returned too much data (%u/%zu bytes)\n",
				payload_len, out_len);
			payload_len = out_len;
		}
		memcpy(out, buf + TPM_HEADER_SIZE + sizeof(uint32_t), payload_len);
		out += payload_len;
		offset += payload_len;
		out_len -= payload_len;
	}
cleanup	:
	if (buf != NULL)
		free(buf);
	return res;
}

int main()
{
	int res = 0;
	tpm_context_t tpm;
	int try = 0;
	while (tpm_chardev[try] != NULL &&
		tpm_open(tpm_chardev[try], &tpm) != 0) {
		try++;
	}
	if (tpm_chardev[try] == NULL) {
		fprintf(stderr, "Error: no TPM found. Quitting.\n");
		res = ENOENT;
		goto cleanup;
	}
	DEBUG_INFO("Using %s\n", tpm.chardev_path);

	/*uint8_t random_stuff[1024] = {1};
	res = tpm_get_random_bytes(&tpm, random_stuff, sizeof(random_stuff));
	printf("Final result:\n");
	DEBUG_HEXDUMP(random_stuff, sizeof(random_stuff));
	*/

	uint8_t read_val[5] = {0};
	res = tpm_read_nvram(&tpm, 0x10, 0, read_val, sizeof(read_val), NULL);
	if (res == TPM_E_BADINDEX)
		fprintf(stderr, "NVRAM area has been removed by a third party.\n");
	else if (res == TPM_E_WRONGPCRVAL)
		fprintf(stderr, "WARNING: PCR values have changed.\n");
	else if (res == TPM_E_AUTH_CONFLICT)
		fprintf(stderr, "NVRAM area requires authentication.\n");
	else {
		printf("Received: \n");
		DEBUG_HEXDUMP(&read_val, 5);
	}

cleanup:
	tpm_close(&tpm);
	return res;
}
