#define _GNU_SOURCE
#include "platform.h"
#include <errno.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <time.h>

int ssh_otp_fstat(int fd, struct ssh_otp_file_info *info) {
    struct stat st;
    if (fstat(fd, &st) != 0) return -1;
    info->uid = st.st_uid;
    info->mode = st.st_mode;
    info->nlink = st.st_nlink;
    info->size = st.st_size;
    return 0;
}

int ssh_otp_boottime(uint64_t *seconds) {
    struct timespec time;
    if (clock_gettime(CLOCK_BOOTTIME, &time) != 0) return -1;
    if (time.tv_sec < 0) {
        errno = EINVAL;
        return -1;
    }
    *seconds = (uint64_t)time.tv_sec;
    return 0;
}

int ssh_otp_sleep(uint32_t milliseconds) {
    struct timespec delay = {
        .tv_sec = milliseconds / 1000,
        .tv_nsec = (long)(milliseconds % 1000) * 1000000L,
    };
    return nanosleep(&delay, 0);
}

int ssh_otp_disable_core_dumps(void) {
    const struct rlimit limit = { .rlim_cur = 0, .rlim_max = 0 };
    return setrlimit(RLIMIT_CORE, &limit);
}
