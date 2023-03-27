#ifndef NSJ_LOGS_H
#define NSJ_LOGS_H

#include <getopt.h>
#include <stdbool.h>
#include <string.h>

enum llevel_t {
    DEBUG = 0,
    INFO,
    WARNING,
    ERROR,
    FATAL,
    HELP,
    HELP_BOLD,
};

#define LOG_HELP(...) logMsg(HELP, __FUNCTION__, __LINE__, false, __VA_ARGS__);
#define LOG_HELP_BOLD(...) \
    logMsg(HELP_BOLD, __FUNCTION__, __LINE__, false, __VA_ARGS__);

#define LOG_D(...)                                                             \
    if (getLogLevel() <= DEBUG) {                                  \
        logMsg(DEBUG, __FUNCTION__, __LINE__, false, __VA_ARGS__); \
    }
#define LOG_I(...)                                                            \
    if (getLogLevel() <= INFO) {                                  \
        logMsg(INFO, __FUNCTION__, __LINE__, false, __VA_ARGS__); \
    }
#define LOG_W(...)                                                               \
    if (getLogLevel() <= WARNING) {                                  \
        logMsg(WARNING, __FUNCTION__, __LINE__, false, __VA_ARGS__); \
    }
#define LOG_E(...)                                                             \
    if (getLogLevel() <= ERROR) {                                  \
        logMsg(ERROR, __FUNCTION__, __LINE__, false, __VA_ARGS__); \
    }
#define LOG_F(...)                                                             \
    if (getLogLevel() <= FATAL) {                                  \
        logMsg(FATAL, __FUNCTION__, __LINE__, false, __VA_ARGS__); \
    }

#define PLOG_D(...)                                                           \
    if (getLogLevel() <= DEBUG) {                                 \
        logMsg(DEBUG, __FUNCTION__, __LINE__, true, __VA_ARGS__); \
    }
#define PLOG_I(...)                                                          \
    if (getLogLevel() <= INFO) {                                 \
        logMsg(INFO, __FUNCTION__, __LINE__, true, __VA_ARGS__); \
    }
#define PLOG_W(...)                                                             \
    if (getLogLevel() <= WARNING) {                                 \
        logMsg(WARNING, __FUNCTION__, __LINE__, true, __VA_ARGS__); \
    }
#define PLOG_E(...)                                                           \
    if (getLogLevel() <= ERROR) {                                 \
        logMsg(ERROR, __FUNCTION__, __LINE__, true, __VA_ARGS__); \
    }
#define PLOG_F(...)                                                           \
    if (getLogLevel() <= FATAL) {                                 \
        logMsg(FATAL, __FUNCTION__, __LINE__, true, __VA_ARGS__); \
    }

void logMsg(enum llevel_t ll, const char *fn, int ln, bool perr, const char *fmt, ...)
    __attribute__((format(printf, 5, 6)));
void logStop(int sig);
void setLogLevel(enum llevel_t ll);
enum llevel_t getLogLevel(void);
void logFile(char *log_file, int log_fd);
bool logSet();

#endif /* NSJ_LOGS_H */