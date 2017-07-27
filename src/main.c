#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>

static const char *tpm_chardev = "/dev/tpm0";

int main()
{
	int res = 0;
	int fd = open(tpm_chardev, O_RDWR | O_SYNC);
	if (fd == -1) {
		const char *hint = "";
		if (errno == EACCES)
			hint = ", am I running as root?";
		else if (errno == EBUSY)
			hint = ", is tcsd running too?";
		fprintf(stderr, "Error: cannot access TPM device %s (%s%s)\n",
			tpm_chardev, strerror(errno), hint);
		res = errno;
		goto cleanup;
	}

cleanup:
	if (fd > 0)
		close(fd);
	return res;
}
