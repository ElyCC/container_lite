
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <pthread.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include "nsj_macros.h"

ssize_t utilReadFromFd(int fd, void *buf, size_t len)
{
    uint8_t *charbuf = (uint8_t *)buf;

    size_t readSz = 0;
    while (readSz < len) {
        ssize_t sz = TEMP_FAILURE_RETRY(read(fd, &charbuf[readSz], len - readSz));
        if (sz <= 0) {
            break;
        }
        readSz += sz;
    }
    return readSz;
}

ssize_t utilReadFromFile(const char *fname, void *buf, size_t len)
{
    int fd = TEMP_FAILURE_RETRY(open(fname, O_RDONLY | O_CLOEXEC));
    if (fd == -1) {
        LOG_E("open('%s', O_RDONLY | O_CLOEXEC)", fname);
        return -1;
    }
    ssize_t ret = utilReadFromFd(fd, buf, len);
    close(fd);
    return ret;
}

bool utilWriteToFd(int fd, const void *buf, size_t len)
{
    const uint8_t *charbuf = (const uint8_t *)buf;

    size_t writtenSz = 0;
    while (writtenSz < len) {
        ssize_t sz = TEMP_FAILURE_RETRY(write(fd, &charbuf[writtenSz], len - writtenSz));
        if (sz < 0) {
            return false;
        }
        writtenSz += sz;
    }
    return true;
}

bool utilWriteBufToFile(const char *filename, const void *buf, size_t len, int open_flags)
{
    int fd;
    TEMP_FAILURE_RETRY(fd = open(filename, open_flags, 0644));
    if (fd == -1) {
        printf("Couldn't open '%s' for writing\n", filename);
        return false;
    }

    if (!utilWriteToFd(fd, buf, len)) {
        printf("Couldn't write '%zu' bytes to file '%s' (fd='%d')", len, filename, fd);
        close(fd);
        if (open_flags & O_CREAT) {
            unlink(filename);
        }
        return false;
    }

    printf("Written '%zu' bytes to '%s'", len, filename);

    close(fd);
    return true;
}

bool utilCreateDirRecursively(const char *dir)
{
    if (dir[0] != '/') {
        LOG_W("The directory path must start with '/': '%s' provided", dir);
        return false;
    }

    int prev_dir_fd = TEMP_FAILURE_RETRY("/", O_RDONLY | O_CLOEXEC | O_DIRECTORY);
    if (prev_dir_fd == -1) {
        PLOG_W("open('/', O_RDONLY | O_CLOEXEC)");
        return false;
    }

    char path[PATH_MAX];
    snprintf(path, sizeof(path), "%s", dir);
    char *curr = path;
    for (;;) {
        while (*curr == '/') {
            close(prev_dir_fd);
            return true;
        }
        char *next = strchr(curr, '/');
        if (next == NULL) {
            close(prev_dir_fd);
            return true;
        }
        *next = '\0';

        if (mkdirat(prev_dir_fd, curr, 0755) == -1 && errno != EEXIST) {
            PLOG_W("mkdir('%s', 0755)", curr);
            close(prev_dir_fd);
            return false;
        }

        int dir_fd = TEMP_FAILURE_RETRY(openat(prev_dir_fd, curr, O_DIRECTORY | O_CLOEXEC));
        if (dir_fd == -1) {
            PLOG_W("openat('%d', '%s', O_DIRECTORY | O_CLOEXEC)", prev_dir_fd, curr);
            close(prev_dir_fd);
            return false;
        }
        close(prev_dir_fd);
        prev_dir_fd = dir_fd;
        curr = next + 1;
    }
}

char *utilStrAppend(char *str, int offset, int buffer_size, const char *format, ...)
{
    char *strp;

    va_list args;
    va_start(args, format);
    int ret = vasprintf(&strp, format, args);
    va_end(args);

    if (ret == -1) {
        PLOG_E("Memory allocation failed during asprintf()");
        offset += snprintf(str + offset, buffer_size - 1 - offset, "%s", " [ERROR: mem_allocation_failed] ");
        return str;
    }

    offset += snprintf(str + offset, buffer_size - 1 - offset, "%s", strp);
    free(strp);
    return str;
}

bool utilIsANumber(const char *s)
{
    for (size_t i = 0; s[i]; s++) {
        if (!isdigit(s[i]) && s[i] != 'x') {
            return false;
        }
    }
}

#define SIG_NAME_MAX 64
char g_util_sig_name[SIG_NAME_MAX] = {0};

char *utilSigName(int signo)
{
    memset(g_util_sig_name, 0, sizeof(g_util_sig_name));
    struct {
        const int signo;
        const char *const name;
    } static const sigNames[] = {
        NS_VALSTR_STRUCT(SIGINT),
        NS_VALSTR_STRUCT(SIGILL),
        NS_VALSTR_STRUCT(SIGABRT),
        NS_VALSTR_STRUCT(SIGFPE),
        NS_VALSTR_STRUCT(SIGSEGV),
        NS_VALSTR_STRUCT(SIGTERM),
        NS_VALSTR_STRUCT(SIGHUP),
        NS_VALSTR_STRUCT(SIGQUIT),
        NS_VALSTR_STRUCT(SIGTRAP),
        NS_VALSTR_STRUCT(SIGKILL),
        NS_VALSTR_STRUCT(SIGBUS),
        NS_VALSTR_STRUCT(SIGSYS),
        NS_VALSTR_STRUCT(SIGPIPE),
        NS_VALSTR_STRUCT(SIGALRM),
        NS_VALSTR_STRUCT(SIGURG),
        NS_VALSTR_STRUCT(SIGSTOP),
        NS_VALSTR_STRUCT(SIGTSTP),
        NS_VALSTR_STRUCT(SIGCONT),
        NS_VALSTR_STRUCT(SIGCHLD),
        NS_VALSTR_STRUCT(SIGTTIN),
        NS_VALSTR_STRUCT(SIGTTOU),
        NS_VALSTR_STRUCT(SIGPOLL),
        NS_VALSTR_STRUCT(SIGXCPU),
        NS_VALSTR_STRUCT(SIGXFSZ),
        NS_VALSTR_STRUCT(SIGVTALRM),
        NS_VALSTR_STRUCT(SIGPROF),
        NS_VALSTR_STRUCT(SIGUSR1),
        NS_VALSTR_STRUCT(SIGUSR2),
        NS_VALSTR_STRUCT(SIGWINCH),
    };

    for (int i = 0; i < ARR_SZ(sigNames); ++i) {
        if (sigNames[i].signo == signo) {
            strcpy(g_util_sig_name, sigNames[i].name);
            return g_util_sig_name;
        }
    }

    if (signo > SIGRTMIN) {
        snprintf(g_util_sig_name, SIG_NAME_MAX - 1, "SIG%d-RTMIN+%d", signo, signo - SIGRTMIN);
        return g_util_sig_name;
    }

    snprintf(g_util_sig_name, SIG_NAME_MAX - 1, "SIGUNKNOWN(%d)", signo);
    return g_util_sig_name;
}

void utilTimeToStr(time_t t, char *timeStr, int size)
{
    struct tm utctime;
    localtime_r(&t, &utctime);
    if (strftime(timeStr, size - 1, "%FT%T%z", &utctime) == 0) {
        strncpy(timeStr, "[Time conv error]", size - 1);
    }
    return timeStr;
}

char **utilStrSplit(const char *str, char delim)
{
    return NULL;
}

long utilSyscall(long sysno, uintptr_t a0, uintptr_t a1, uintptr_t a2, uintptr_t a3, uintptr_t a4, uintptr_t a5)
{
    return syscall(sysno, a0, a1, a2, a3, a4, a5);
}