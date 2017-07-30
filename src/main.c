#include "main.h"
#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <fcntl.h>
#include <arpa/inet.h>

static const char* tpm_chardev[] = {
	"/dev/tpm",
	"/dev/tpm0",
	"/udev/tpm0",
	NULL
};

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
	init_local_random_generator(tpm_entropy, sizeof(tpm_entropy));
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

void serialize_uint32(uint32_t in, tpm_buffer_t *buffer)
{
	in = htonl(in);
	memcpy(&(buffer->contents.bytes[buffer->pos]), &in, 4);
	buffer->pos += 4;
}

void serialize_uint16(uint16_t in, tpm_buffer_t *buffer)
{
	in = htons(in);
	memcpy(&(buffer->contents.bytes[buffer->pos]), &in, 2);
	buffer->pos += 2;
}

void serialize_uint8(uint8_t in, tpm_buffer_t *buffer)
{
	buffer->contents.bytes[buffer->pos] = in;
	buffer->pos++;
}

void serialize(uint8_t *in, size_t in_len, tpm_buffer_t *buffer)
{
	memcpy(&buffer->contents.bytes[buffer->pos], in, in_len);
	buffer->pos += in_len;
}

void serialize_reset(tpm_buffer_t *buffer)
{
	buffer->pos = 0;
}

uint32_t deserialize_uint32(tpm_buffer_t *buffer)
{
	buffer->pos += 4;
	return ((buffer->contents.bytes[buffer->pos-4] << 24) |
		(buffer->contents.bytes[buffer->pos-3] << 16) |
		(buffer->contents.bytes[buffer->pos-2] << 8) |
		(buffer->contents.bytes[buffer->pos-1]));
}

uint16_t deserialize_uint16(tpm_buffer_t *buffer)
{
	buffer->pos += 2;
	return ((buffer->contents.bytes[buffer->pos-2] << 8) |
		(buffer->contents.bytes[buffer->pos-1]));
}

uint8_t deserialize_uint8(tpm_buffer_t *buffer)
{
	return buffer->contents.bytes[buffer->pos++];
}

void deserialize(uint8_t *out, size_t out_len, tpm_buffer_t *buffer)
{
	memcpy(out, &buffer->contents.bytes[buffer->pos], out_len);
	buffer->pos += out_len;
}

int tpm_get_random_bytes(tpm_context_t *tpm, uint8_t *out, size_t out_len)
{
	if (out == NULL || out_len > MAX_INT)
		return -EINVAL;
	int res = 0;
	tpm_buffer_t *buf = malloc(sizeof(tpm_buffer_t) + sizeof(uint32_t) + out_len);
	if (buf == NULL)
		return ENOMEM;
	while (out_len > 0) {
		// Header
		serialize_reset(buf);
		serialize_uint16(TPM_TAG_RQU_COMMAND, buf);
		serialize_uint32(TPM_HEADER_SIZE + sizeof(uint32_t), buf);
		serialize_uint32(TPM_ORD_GetRandom, buf);
		// Params
		serialize_uint32(out_len, buf);
		DEBUG_HEXDUMP("Sending rand request", buf->contents.bytes, buf->pos);
		size_t req_sent = write(tpm->chardev_fd, &buf->contents.bytes, buf->pos);
		if (req_sent != buf->pos) {
			fprintf(stderr, "Error: truncated write to TPM device (%s)\n",
				strerror(errno));
			res = errno;
			goto cleanup;
		}
		size_t read_len = read(tpm->chardev_fd, &buf->contents.bytes,
				TPM_HEADER_SIZE + sizeof(uint32_t) + out_len);
		DEBUG_HEXDUMP("Rand response received", buf, read_len);
		if (read_len < TPM_HEADER_SIZE) {
			fprintf(stderr, "Error: truncated read from TPM (%zu bytes)\n", read_len);
			res = EINVAL;
			goto cleanup;
		}
		serialize_reset(buf);
		uint16_t resp_tag = deserialize_uint16(buf);
		uint32_t resp_len = deserialize_uint32(buf);
		uint32_t resp_code = deserialize_uint32(buf);
		if (resp_tag != TPM_TAG_RSP_COMMAND) {
			fprintf(stderr, "Error: invalid response tag 0x%04X\n", resp_tag);
			res = EINVAL;
			goto cleanup;
		} else if (resp_code != 0) {
			DEBUG_WARN("TPM returned error code %u\n", resp_code);
			res = resp_code;
			goto cleanup;
		}
		uint32_t payload_len = deserialize_uint32(buf);
		if (resp_len != TPM_HEADER_SIZE + sizeof(uint32_t) + payload_len) {
			fprintf(stderr, "Error: malformed TPM response, invalid payload length\n");
			res = EINVAL;
			goto cleanup;
		} else if (payload_len > out_len) {
			DEBUG_WARN("TPM returned too much data (%u/%zu bytes)\n",
				payload_len, out_len);
			payload_len = out_len;
		}
		deserialize(out, payload_len, buf);
		out += payload_len;
		out_len -= payload_len;
	}
cleanup:
	free(buf);
	return res;
}

int tpm_auth_oiap(tpm_context_t *tpm, tpm_oiap_auth_t *auth,
		const tpm_buffer_t *main_req, const sha1_digest_t *passwd_digest)
{
	// Request a nonce from the TPM
	int res = 0;
	tpm_buffer_t *buf = malloc(sizeof(tpm_buffer_t) + sizeof(uint32_t) + sizeof(tpm_nonce_t));
	if (buf == NULL)
		return ENOMEM;
	serialize_reset(buf);
	serialize_uint16(TPM_TAG_RQU_COMMAND, buf);
	serialize_uint32(TPM_HEADER_SIZE, buf);
	serialize_uint32(TPM_ORD_OIAP, buf);
	DEBUG_HEXDUMP("Sending OIAP request", buf->contents.bytes, buf->pos);
	size_t req_sent = write(tpm->chardev_fd, &buf->contents.bytes, buf->pos);
	if (req_sent != buf->pos) {
		fprintf(stderr, "Error: truncated write to TPM device (%s)\n",
				strerror(errno));
		res = errno;
		goto cleanup;
	}
	size_t read_len = read(tpm->chardev_fd, &buf->contents.bytes,
			TPM_HEADER_SIZE + sizeof(uint32_t) + sizeof(tpm_nonce_t));
	DEBUG_HEXDUMP("OIAP Response received", buf->contents.bytes, read_len);
	if (read_len < TPM_HEADER_SIZE) {
		fprintf(stderr, "Error: truncated read from TPM (%zu bytes)\n", read_len);
		res = EINVAL;
		goto cleanup;
	}
	serialize_reset(buf);
	uint16_t resp_tag = deserialize_uint16(buf);
	uint32_t resp_len = deserialize_uint32(buf);
	uint32_t resp_code = deserialize_uint32(buf);
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
	auth->handle = deserialize_uint32(buf);
	DEBUG_INFO("Assigned auth handle %d\n", auth->handle);
	deserialize((uint8_t*)&auth->nonce_tpm, sizeof(auth->nonce_tpm), buf);
	auth->continue_auth_session = 0;
	// Generate our own nonce
	get_local_random_bytes((uint8_t*)&auth->nonce_local, sizeof(auth->nonce_local));
	// Get a digest of the request to be authenticated, minus its
	// tag (16-bit int) and payload length (32-bit int)
	sha1((uint8_t*)&main_req->contents.header.code,
		main_req->pos - offsetof(tpm_packet_header_t, code),
		&auth->request_digest);
	// Get a HMAC of that digest + the TPM's nonce + our nonce + the
	// "continue session" parameter, with the secret's digest as a key
	hmac_sha1((uint8_t*)&auth->request_digest, TPM_OIAP_AUTH_SIZE,
		(uint8_t*)passwd_digest, SHA1_DIGEST_SIZE, &auth->hmac);
cleanup:
	free(buf);
	return res;
}

int tpm_read_nvram(tpm_context_t *tpm, int addr, int offset, uint8_t *out,
                   size_t out_len, const sha1_digest_t *owner_passwd_digest)
{
	if (out == NULL || out_len > MAX_INT)
		return -EINVAL;
	int res = 0;
	tpm_buffer_t *buf = malloc(sizeof(tpm_buffer_t) + sizeof(tpm_oiap_auth_t) + sizeof(uint32_t) + out_len);
	if (buf == NULL)
		return ENOMEM;
	while (out_len > 0) {
		DEBUG_INFO("Requesting %zu bytes at offset %d from index %d\n",
			out_len, offset, addr);
		// Header
		uint16_t tag = (owner_passwd_digest == NULL ? TPM_TAG_RQU_COMMAND : TPM_TAG_RQU_AUTH1_COMMAND);
		serialize_reset(buf);
		serialize_uint16(tag, buf);
		serialize_uint32(TPM_HEADER_SIZE + sizeof(uint32_t)*3, buf);
		serialize_uint32(TPM_ORD_NV_ReadValue, buf);
		// Params
		serialize_uint32((uint32_t)addr, buf);
		serialize_uint32((uint32_t)offset, buf);
		serialize_uint32((uint32_t)out_len, buf);
		tpm_oiap_auth_t auth = {0};
		if (owner_passwd_digest != NULL) {
			buf->contents.header.total_size = htonl(buf->pos + sizeof(uint32_t) + sizeof(tpm_nonce_t) + 1 + sizeof(auth.hmac));
			res = tpm_auth_oiap(tpm, &auth, buf, owner_passwd_digest);
			if (res != 0)
				goto cleanup;
			serialize_uint32((uint32_t)auth.handle, buf);
			serialize((uint8_t*)&auth.nonce_local, sizeof(tpm_nonce_t), buf);
			serialize_uint8(auth.continue_auth_session, buf);
			serialize((uint8_t*)&auth.hmac, sizeof(auth.hmac), buf);
		}
		DEBUG_HEXDUMP("Sending NV_Read request", buf->contents.bytes, buf->pos);
		size_t req_sent = write(tpm->chardev_fd, buf->contents.bytes, buf->pos);
		if (req_sent != buf->pos) {
			fprintf(stderr, "Error: truncated write to TPM device (%s)\n",
				strerror(errno));
			res = errno;
			goto cleanup;
		}
		size_t read_len = read(tpm->chardev_fd, buf->contents.bytes, 9999); //FIXME: variable read len?
		DEBUG_HEXDUMP("Received NV_Read response", buf->contents.bytes, read_len);
		if (read_len < TPM_HEADER_SIZE) {
			fprintf(stderr, "Error: truncated read from TPM (%zu bytes)\n", read_len);
			res = EINVAL;
			goto cleanup;
		}
		serialize_reset(buf);
		uint16_t resp_tag = deserialize_uint16(buf);
		uint32_t resp_len = deserialize_uint32(buf);
		uint32_t resp_code = deserialize_uint32(buf);
		if ((owner_passwd_digest == NULL && resp_tag != TPM_TAG_RSP_COMMAND) ||
				(owner_passwd_digest != NULL && resp_tag != TPM_TAG_RSP_AUTH1_COMMAND)) {
			fprintf(stderr, "Error: invalid response tag 0x%04X\n", resp_tag);
			res = EINVAL;
			goto cleanup;
		} else if (resp_code != 0) {
			DEBUG_WARN("TPM returned error code %u\n", resp_code);
			res = resp_code;
			goto cleanup;
		} else if (resp_len != read_len || resp_len < TPM_HEADER_SIZE + sizeof(uint32_t)) {
			fprintf(stderr, "Error: truncated read from TPM (%zu/%d bytes)\n",
				read_len, resp_len);
			res = E2BIG;
			goto cleanup;
		}
		uint32_t payload_len = deserialize_uint32(buf);
		if (payload_len > out_len) {
			fprintf(stderr, "Error: TPM returned %u instead of %zu bytes)\n",
				payload_len, out_len);
			res = EINVAL;
			goto cleanup;
		} else if (resp_len < TPM_HEADER_SIZE + sizeof(uint32_t) + payload_len) {
			fprintf(stderr, "Error: truncated read from TPM (%d/%zu bytes)\n",
				resp_len, TPM_HEADER_SIZE + sizeof(uint32_t) + payload_len);
			res = E2BIG;
			goto cleanup;
		}
		deserialize(out, payload_len, buf);
		out += payload_len;
		offset += payload_len;
		out_len -= payload_len;
		if (owner_passwd_digest != NULL) {
			if (resp_len < TPM_HEADER_SIZE + sizeof(uint32_t) + payload_len) {
				fprintf(stderr, "Error: truncated read from TPM (%d/%zu bytes)\n",
					resp_len, TPM_HEADER_SIZE + sizeof(uint32_t) + payload_len);
				res = E2BIG;
				goto cleanup;
			}
			deserialize((uint8_t*)&auth.nonce_tpm, sizeof(tpm_nonce_t), buf);
			tpm_nonce_t local_nonce_bis;
			deserialize((uint8_t*)&local_nonce_bis, sizeof(tpm_nonce_t), buf);
			if (!memcmp(&auth.nonce_local, &local_nonce_bis, sizeof(tpm_nonce_t))) {
				fprintf(stderr, "Error: TPM returned a different nonce from ours\n");
				res = EINVAL;
				goto cleanup;
			}
			auth.continue_auth_session = deserialize_uint8(buf);
			sha1_digest_t expected_hmac;
			sha1_digest_t received_hmac;
			deserialize((uint8_t*)&received_hmac, sizeof(sha1_digest_t), buf);
			// TODO: verify response HMAC
			if (!memcmp(&expected_hmac, &buf[14+payload_len+sizeof(tpm_nonce_t)*2+1], sizeof(sha1_digest_t))) {
				fprintf(stderr, "Error: TPM failed to authenticate via OIAP\n");
				goto cleanup;
			}
		}
	}
cleanup:
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
	DEBUG_HEXDUMP("Final result", random_stuff, sizeof(random_stuff));
	*/

	sha1_digest_t owner_passwd_digest;
	sha1((uint8_t*)"pass", 4, &owner_passwd_digest);
	DEBUG_HEXDUMP("Password digest", &owner_passwd_digest, SHA1_DIGEST_SIZE);

	uint8_t read_val[5] = {0};
	res = tpm_read_nvram(&tpm, 0x10, 0, read_val, sizeof(read_val), &owner_passwd_digest);
	if (res == TPM_E_BADINDEX)
		fprintf(stderr, "NVRAM area has been removed by a third party.\n");
	else if (res == TPM_E_WRONGPCRVAL)
		fprintf(stderr, "WARNING: PCR values have changed.\n");
	else if (res == TPM_E_AUTH_CONFLICT)
		fprintf(stderr, "NVRAM area requires authentication.\n");
	else if (res == TPM_E_AUTHFAIL)
		fprintf(stderr, "Invalid password, authentication failure\n");
	else
		DEBUG_HEXDUMP("Received", &read_val, 5);

cleanup:
	tpm_close(&tpm);
	return res;
}
