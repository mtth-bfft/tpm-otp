#include <stdint.h>
#include "crypto.h"

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
#define DEBUG_INFO(...) do { } while (0)
#define DEBUG_WARN(...) do { } while (0)
#define DEBUG_HEXDUMP(blob, len) do { } while(0)
#endif

#define MAX_PATH_LEN 255
#define MAX_INT 0xFFFFFFFF

// Constants from TPM v1.2 specifications
#define TPM_TAG_RQU_COMMAND ((uint16_t)(0x00C1))
#define TPM_TAG_RQU_AUTH1_COMMAND ((uint16_t)(0x00C2))
#define TPM_TAG_RSP_COMMAND (uint16_t)(0x00C4)
#define TPM_ORD_GetRandom ((uint32_t)0x46)
#define TPM_ORD_NV_ReadValue ((uint32_t)0xCF)
#define TPM_ORD_OIAP ((uint32_t)0x0A)
#define TPM_E_BADINDEX 0x00000002
#define TPM_E_WRONGPCRVAL 0x00000018
#define TPM_E_AUTH_CONFLICT 0x0000003B
#define TPM_HEADER_SIZE (sizeof(tpm_packet_header_t))

// Structures from TPM v1.2 specifications
typedef struct __attribute__((__packed__)) {
	uint16_t tag;
	uint32_t total_size; // total number of bytes, including header
	uint32_t code;
} tpm_packet_header_t;

typedef struct __attribute__((__packed__)) {
	uint8_t bytes[20];
} tpm_nonce_t;

typedef struct __attribute__((__packed__)) {
	uint32_t handle;
	// start of variables covered by 'hmac'
	tpm_nonce_t nonce_local;
	tpm_nonce_t nonce_tpm;
	int8_t continue_auth_session;
	// end of variables covered by 'hmac'
	sha1_digest_t hmac;
} tpm_oiap_auth_t;
#define TPM_OIAP_AUTH_SIZE (offsetof(tpm_oiap_auth_t, hmac)-offsetof(tpm_oiap_auth_t, nonce_local))

// Software-specific structures
typedef struct {
	int chardev_fd;
	char chardev_path[MAX_PATH_LEN];
} tpm_context_t;

typedef struct {
	size_t pos;
	union {
		tpm_packet_header_t header;
		uint8_t bytes[1];
	} contents;
} tpm_buffer_t;

/**
 * Opens a file descriptor to the given character device, or prints an error
 * message if something unexpected prevents it. Returns 0 if and only if the
 * tpm_context_t was successfully initialised.
 */
extern int tpm_open(const char *path, tpm_context_t *tpm);

/**
 * Releases all allocated resources associated with the given TPM context.
 * Returns 0 if and only if all ressources were deallocated successfully.
 */
extern int tpm_close(tpm_context_t *tpm);

/**
 * Ask the TPM for cryptographically securely generated random bytes.
 * This function may block for some time, since multiple requests might be
 * necessary to get the requested number of bytes (some TPMs give ~100 bytes
 * at a time).
 */
extern int tpm_get_random_bytes(tpm_context_t *tpm, uint8_t *out, size_t out_len);

/**
 * Performs OIAP authentication with the TPM, given a pending request. This
 * functions sends multiple requests to the TPM, to retrieve a nonce and then
 * to authenticate using the given secret, so no other request must be sent
 * in the meantime. Returns 0 if and only if authentication and authorisation
 * were successful.
 */
extern int tpm_auth_oiap(tpm_context_t *tpm, tpm_oiap_auth_t *auth,
		tpm_buffer_t *req, const sha1_digest_t *passwd_digest);
