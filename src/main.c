#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>

#ifdef DEBUG
#define DEBUG_INFO(...) fprintf(stderr, " [+] " __VA_ARGS__)
#else
#define DEBUG_INFO(...)
#endif

static const char* tpm_chardev[] = {
	"/dev/tpm",
	"/dev/tpm0",
	"/udev/tpm0",
	NULL
};

/**
 * Returns a file descriptor to the given path, or -1 if an error occurs.
 * Prints an error message if something unexpected prevents opening the
 * character device.
 */
int get_tpm_fd(const char *path)
{
	int fd = open(path, O_RDWR | O_SYNC);
	if (fd == -1 && errno != ENOENT) {
		const char *hint = "";
		if (errno == EACCES)
			hint = ", am I running as root?";
		else if (errno == EBUSY)
			hint = ", is tcsd running too?";
		fprintf(stderr, "Error: cannot access TPM device %s (%s%s)\n",
			path, strerror(errno), hint);
		return errno;
	}
	return fd;
}

int main()
{
	int res = 0;
	int fd = -1;
	const char *chardev = NULL;
	for (int try = 0; tpm_chardev[try] != NULL; try++) {
		fd = get_tpm_fd(tpm_chardev[try]);
		if (fd != 0) {
			chardev = tpm_chardev[try];
			break;
		}
	}
	if (fd < 0) {
		fprintf(stderr, "Error: no TPM found. Quitting.\n");
		res = ENOENT;
		goto cleanup;
	}
	DEBUG_INFO("Using %s\n", chardev);

cleanup:
	if (fd > 0)
		close(fd);
	return res;
}
