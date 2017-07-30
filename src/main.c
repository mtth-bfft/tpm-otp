#include "main.h"
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>

static const char* tpm_chardev[] = {
	"/dev/tpm",
	"/dev/tpm0",
	"/udev/tpm0",
	NULL
};

static const char* local_rand_chardev[] = {
	"/dev/urandom",
	"/dev/random",
	NULL
};

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
		if (read_len <= 0) {
			fprintf(stderr, "Error: unable to read from random number source (%s)\n",
				strerror(errno));
			exit(errno);
		}
		out_len -= read_len;
		out += read_len;
	} while(out_len > 0);
}

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
	DEBUG_INFO("Successfully opened %s. Requesting entropy...\n", tpm->chardev_path);
	// Stir the local entropy pool thanks to the TPM's one, in case we're
	// running low during boot
	uint8_t tpm_entropy[255] = {0};
	int res = tpm_get_random_bytes(tpm, tpm_entropy, sizeof(tpm_entropy));
	if (res != 0)
		DEBUG_WARN("Unable to stir local entropy pool: error %d\n", res);
	DEBUG_INFO("Seeding local entropy pool using %zu bytes from TPM...\n",
		sizeof(tpm_entropy));
	get_local_random_bytes(tpm_entropy, sizeof(tpm_entropy));
	//TODO: Stir the TPM's entropy pool thanks to the local one
	return 0;
}

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

int tpm_auth_oiap(tpm_context_t *tpm, tpm_oiap_auth_t *auth, uint8_t *req,
		size_t main_req_len, const sha1_digest_t *passwd_digest)
{
	// Request a nonce from the TPM
	int res = 0;
	uint8_t buf[TPM_HEADER_SIZE] = {0};
	uint64_t req_len = 0;
	req_len += serialize_uint16(buf, req_len, TPM_TAG_RQU_COMMAND);
	req_len += serialize_uint32(buf, req_len, TPM_HEADER_SIZE);
	req_len += serialize_uint32(buf, req_len, TPM_ORD_OIAP);
	DEBUG_HEXDUMP(buf, req_len);
	size_t req_sent = write(tpm->chardev_fd, buf, req_len);
	if (req_sent != req_len) {
		fprintf(stderr, "Error: truncated write to TPM device (%s)\n",
				strerror(errno));
		res = errno;
		goto cleanup;
	}
	size_t read_len = read(tpm->chardev_fd, buf, TPM_HEADER_SIZE + sizeof(uint32_t) + sizeof(nonce_t));
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
	} else if (resp_len != TPM_HEADER_SIZE + sizeof(uint32_t) + sizeof(sha1_digest_t)) {
		fprintf(stderr, "Error: malformed response, invalid payload length\n");
		res = EINVAL;
		goto cleanup;
	}
	auth->handle = deserialize_uint32(&buf[10]);
	memcpy(&auth->nonce_tpm, &buf[14], sizeof(auth->nonce_tpm));
	DEBUG_INFO("Auth handle acquired = %d\n", auth->handle);
	DEBUG_INFO("TPM sent auth nonce:\n");
	DEBUG_HEXDUMP(&auth->nonce_tpm, sizeof(auth->nonce_tpm));
	auth->continue_auth_session = 0;
	// Generate our own nonce
	get_local_random_bytes((uint8_t*)&auth->nonce_local, sizeof(auth->nonce_local));
	// Get a digest of the request to be authenticated
	sha1_digest_t req_digest = {0};
	sha1(req, main_req_len, &req_digest);
	// Get a HMAC of that digest + the TPM's nonce + our nonce + the
	// "continue session" parameter, with the secret's digest as a key
	hmac_sha1((uint8_t*)auth, TPM_OIAP_AUTH_SIZE, (uint8_t*)passwd_digest,
		SHA1_DIGEST_SIZE, &auth->hmac);
cleanup:
	return res;
}

int tpm_read_nvram(tpm_context_t *tpm, int addr, int offset, uint8_t *out,
                   size_t out_len, const sha1_digest_t *owner_passwd_digest)
{
	if (out == NULL || out_len > MAX_INT)
		return -EINVAL;
	int res = 0;
	uint8_t *buf = malloc(TPM_HEADER_SIZE + sizeof(uint32_t) + out_len);
	if (buf == NULL)
		return ENOMEM;
	while (out_len > 0) {
		DEBUG_INFO("Requesting %zu bytes at offset %d from index %d\n",
			out_len, offset, addr);
		// Header
		uint64_t req_len = 0;
		uint16_t tag = (owner_passwd_digest == NULL ? TPM_TAG_RQU_COMMAND : TPM_TAG_RQU_AUTH1_COMMAND);
		req_len += serialize_uint16(buf, req_len, tag);
		req_len += serialize_uint32(buf, req_len, TPM_HEADER_SIZE + sizeof(uint32_t)*3);
		req_len += serialize_uint32(buf, req_len, TPM_ORD_NV_ReadValue);
		// Params
		req_len += serialize_uint32(buf, req_len, (uint32_t)addr);
		req_len += serialize_uint32(buf, req_len, (uint32_t)offset);
		req_len += serialize_uint32(buf, req_len, (uint32_t)out_len);
		DEBUG_HEXDUMP(buf, req_len);
		if (owner_passwd_digest != NULL) {
			DEBUG_INFO("Performing OIAP authorization...\n");
			tpm_oiap_auth_t auth = {0};
			res = tpm_auth_oiap(tpm, &auth, buf, req_len, owner_passwd_digest);
			DEBUG_INFO("OIAP result = %d\n", res);
		}
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
