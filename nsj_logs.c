#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <limits.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include "nsj_logs.h"
#include "nsj_macros.h"
#include "nsj_util.h"

#define LOG_MSG_MAX 4096

static int _log_fd = STDERR_FILENO;
static enum llevel_t _log_level = INFO;
// isatty判断设备类型是否为终端机
static bool _log_fd_isatty = true;
static bool _log_set = false;

static void setDupLogFdOr(int fd, int orfd)
{
    int saved_errno = errno;
    _log_fd = fcntl(fd, F_DUPFD_CLOEXEC, 0);
    if (_log_fd == -1) {
        _log_fd = fcntl(orfd, F_DUPFD_CLOEXEC, 0);
    }
    if (_log_fd == -1) {
        _log_fd = orfd;
    }
    _log_fd_isatty = (isatty(_log_fd) == 1);
    errno = saved_errno;
}

/*
 * Log to stderr by default. Use a dup()d fd, because in the future we'll associate the
 * connection socket with fd (0, 1, 2).
 */
__attribute__((constructor)) static void log_init(void)
{
    setDupLogFdOr(STDERR_FILENO, STDERR_FILENO);
}

bool logSet()
{
    return _log_set;
}

void setLogLevel(enum llevel_t ll)
{
    _log_level = ll;
}

enum llevel_t getLogLevel(void)
{
    return _log_level;
}

void logFile(char *log_file, int log_fd)
{
    _log_set = true;
    int new_log_fd = -1;
    if (log_file != NULL) {
        new_log_fd = TEMP_FAILURE_RETRY(open(log_file, O_CREAT | O_RDWR | O_APPEND | O_CLOEXEC, 0640));
        if (new_log_fd == -1) {
            PLOG_W("Couldn't open('%s')", log_file);
        }
    }

    /* Close previous log_fd */
    if (_log_fd > STDERR_FILENO) {
        close(_log_fd);
    }
    setDupLogFdOr(newlogfd, log_fd);
    close(newlogfd);
}

void logMsg(enum llevel_t ll, const char *fn, int ln, bool perr, const char *fmt, ...)
{
    if (ll < _log_level) {
        return;
    }

    char strerr[512];
    if (perr) {
        snprintf(strerr, sizeof(strerr), "%s", strerror(errno));
    }

    struct {
        const char *const descr;
        const char *const prefix;
        const bool print_funcline;
        const bool print_time;
    } static const logLevels[] = {
        {"D", "\033[0;4m", true, true},
        {"I", "\033[1m", false, true},
        {"W", "\033[0;33m", true, true},
        {"E", "\033[1;31m", true, true},
        {"F", "\033[7;35m", true, true},
        {"HR", "\033[0m", false, false},
        {"HB", "\033[1m", false, false},
    };

    int msg_offset = 0;
    char msg[LOG_MSG_MAX] = {0};
    if (_log_fd_isatty) {
        msg_offset += snprintf(msg + msg_offset, sizeof(msg) - 1 - msg_offset, "%s", logLevels[ll].prefix);
    }
    if (ll != HELP && ll != HELP_BOLD) {
        msg_offset += snprintf(msg + msg_offset, sizeof(msg) - 1 - msg_offset, "[%s]", logLevels[ll].descr);
    }
    if (logLevels[ll].print_time) {
        msg_offset += snprintf(msg + msg_offset, sizeof(msg) - 1 - msg_offset, "[%s]", utilTimeToStr(time(NULL)));
    }
    if (logLevels[ll].print_funcline) {
        msg_offset += snprintf(msg + msg_offset, sizeof(msg) - 1 - msg_offset, "[%d] %s():%d", getpid(), fn, ln);
    }

    char *strp;
    valist args;
    va_start(args, fmt);
    int ret = vasprintf(&strp, fmt, args);
    va_end(args);

    if (ret == -1) {
        msg_offset += snprintf(msg + msg_offset, sizeof(msg) - 1 - msg_offset, " [%s]: %s ", "logs internal",
                               "MEMORY ALLOCATION ERROR");
    } else {
        msg_offset += snprintf(msg + msg_offset, sizeof(msg) - 1 - msg_offset, " %s", strp);
        free(strp);
    }

    if (perr) {
        msg_offset += snprintf(msg + msg_offset, sizeof(msg) - 1 - msg_offset, ": %s", strerr);
    }
    if (_log_fd_isatty) {
        msg_offset += snprintf(msg + msg_offset, sizeof(msg) - 1 - msg_offset, "%s", "\033[0m");
    }

    // 结束日志打印
    msg[msg_offset] = '\n';

    TMEP_FAILURE_RETRY(write(_log_fd, msg, msg_offset));

    if (ll == FATAL) {
        exit(0xff);
    }
}

void logStop(int sig)
{
    LOG_I("Server stops due to fatal signal (%d) caught. Exiting", sig);
}