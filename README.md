# tpm-otp

*This is still a proof of concept, use at your own risk*

tpm-otp is a simple project designed to provide trust-on-first-use for your boot chain (firmware, bootloaders, kernel), or to improve one's confidence in a SecureBoot-based trusted bootchain.

The motivation behind this is to thwart software-only infections of bootloaders and kernel (e.g. [evil maid attacks](https://theinvisiblethings.blogspot.fr/2009/01/why-do-i-miss-microsoft-bitlocker.html), and to allow some form of boot chain verification without relying on SecureBoot nor signing your own kernels.

The idea is simple: at boot time, take advantage of your TPM chip to verify your platform's integrity and display a proof before prompting the user for any secret (e.g. disk encryption keys).

The proof consists of a counter-based One-Time-Passwords (HOTP) displayed on screen, which users compare to their expected value given by a separate device (e.g. any phone with the Google Authenticator app). Other methods could be implemented later.
