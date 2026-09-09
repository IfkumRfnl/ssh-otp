#ifndef SSH_OTP_PLATFORM_H
#define SSH_OTP_PLATFORM_H
#include <stdint.h>

/* libc owns stat/timespec/rlimit layouts. Musl timespec contains bitfields
 * that Zig's C translator cannot represent, even on x86_64. */
struct ssh_otp_file_info {
    uint32_t uid;
    uint32_t mode;
    uint64_t nlink;
    int64_t size;
};

int ssh_otp_fstat(int fd, struct ssh_otp_file_info *info);
int ssh_otp_boottime(uint64_t *seconds);
int ssh_otp_sleep(uint32_t milliseconds);
int ssh_otp_disable_core_dumps(void);
#endif
