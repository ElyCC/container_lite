#include <linux/sched.h>
#include <sched.h>
#include <signal.h>
#include <stddef.h>
#include <sys/prctl.h>
#include <unistd.h>

#include "nsj_logs.h"
#include "nsj_pid.h"
#include "nsj_subproc.h"

bool pidInitNs(nsjconf_t *nsjconf)
{
    if (nsjconf->mode != MODE_STANDALONE_EXECVE) {
        return true;
    }
    if (!nsjconf->clone_newpid) {
        return true;
    }

    LOG_D("Creating a dummy 'init' process");

    pid_t pid = subprocCloneProc(CLONE_FS, 0);
    if (pid == -1) {
        PLOG_E("Couldn't create a dummy init process");
        return false;
    }
    if (pid > 0) {
        return true;
    }

    if (prctl(PR_SET_PDEATHSIG, SIGKILL, 0UL, 0UL, 0UL) == -1) {
        PLOG_W("(prctl(PR_SET_PDEATHSIG, SIGKILL) failed");
    }
    if (prctl(PR_SET_NAME, "ns-init", 0UL, 0UL, 0UL) == -1) {
        PLOG_W("(prctl(PR_SET_NAME, 'init') failed");
    }
    if (prctl(PR_SET_DUMPABLE, 0UL, 0UL, 0UL, 0UL) == -1) {
        PLOG_W("(prctl(PR_SET_DUMPABLE, 0) failed");
    }

    	/* Act sort-a like a init by reaping zombie processes */
	struct sigaction sa;
	sa.sa_handler = SIG_DFL;
	sa.sa_flags = SA_NOCLDWAIT | SA_NOCLDSTOP;
	sa.sa_restorer = NULL;
	sigemptyset(&sa.sa_mask);

	if (sigaction(SIGCHLD, &sa, NULL) == -1) {
		PLOG_W("Couldn't set sighandler for SIGCHLD");
	}

	for (;;) {
		pause();
	}
}