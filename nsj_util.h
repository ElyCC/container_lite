#ifndef NSJ_UTIL_H
#define NSJ_UTIL_H

#include <inttypes.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define RETURN_ON_FAILURE(expr)       \
	do {                          \
		if (!(expr)) {        \
			return false; \
		}                     \
	} while (0)

ssize_t utilReadFromFd(int fd, void *buf, size_t len);
bool utilWriteToFd(int fd, const void *buf, size_t len);
bool utilWriteBufToFile(const char* filename, const void* buf, size_t len, int open_flags);

char *utilStrAppend(char *str, int offset, int buffer_size, const char *format, ...);

bool utilIsANumber(const char* s);

#endif /* NSJ_UTIL_H */