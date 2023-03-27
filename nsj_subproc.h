#ifndef NSJ_SUBPROC_H
#define NSJ_SUBPROC_H

#include <stdbool.h>
#include <string.h>
#include <unistd.h>

#include "nsj_nsjail.h"

/* 0 - network connection limit reached, -1 - error */
pid_t subprocRunChild(nsjconf_t *nsjconf, int listen_fd, int fd_in, int fd_out, int fd_err);
int subprocCountProc(nsjconf_t *nsjconf);
void subprocDisplayProc(nsjconf_t *nsjconf);
void subprocKillAndReapAll(nsjconf_t *nsjconf, int signal);
/* Returns the exit code of the first failing subprocess, or 0 if none fail */
int subprocReapProc(nsjconf_t *nsjconf);
int subprocSystemExe(const char *const args, char **env);
pid_t subprocCloneProc(uintptr_t flags, int exit_signal);

#endif /* NSJ_SUBPROC_H */