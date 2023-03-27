#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <linux/sched.h>
#include <sched.h>
#include <setjmp.h>
#include <signal.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "nsj_cgroupv1.h"
#include "nsj_cgroupv2.h"
#include "nsj_contain.h"
#include "nsj_logs.h"
#include "nsj_macros.h"
#include "nsj_net.h"
#include "nsj_nsjail.h"
#include "nsj_sandbox.h"
#include "nsj_user.h"
#include "nsj_util.h"

#if !defined(CLONE_NEWCGROUP)
#define CLONE_NEWCGROUP 0x02000000
#endif /* !defined(CLONE_NEWCGROUP) */

#if !defined(CLONE_NEWTIME)
#define CLONE_NEWTIME 0x00000080
#endif /* !defined(CLONE_NEWTIME) */

#define ARG_ARRAY_MAX 4096

#define SUBPROC_STR_MAX 256
char g_flags_to_str_res[SUBPROC_STR_MAX] = {0};
static char *cloneFlagsToStr(uintptr_t flags)
{
    struct {
        const uint64_t flag;
        const char *const name;
    } static const cloneFlags[] = {
        NS_VALSTR_STRUCT(CLONE_NEWTIME),
        NS_VALSTR_STRUCT(CLONE_VM),
        NS_VALSTR_STRUCT(CLONE_FS),
        NS_VALSTR_STRUCT(CLONE_FILES),
        NS_VALSTR_STRUCT(CLONE_SIGHAND),
#if !defined(CLONE_PIDFD)
#define CLONE_PIDFD 0x00001000
#endif
        NS_VALSTR_STRUCT(CLONE_PIDFD),
        NS_VALSTR_STRUCT(CLONE_PTRACE),
        NS_VALSTR_STRUCT(CLONE_VFORK),
        NS_VALSTR_STRUCT(CLONE_PARENT),
        NS_VALSTR_STRUCT(CLONE_THREAD),
        NS_VALSTR_STRUCT(CLONE_NEWNS),
        NS_VALSTR_STRUCT(CLONE_SYSVSEM),
        NS_VALSTR_STRUCT(CLONE_SETTLS),
        NS_VALSTR_STRUCT(CLONE_PARENT_SETTID),
        NS_VALSTR_STRUCT(CLONE_CHILD_CLEARTID),
        NS_VALSTR_STRUCT(CLONE_DETACHED),
        NS_VALSTR_STRUCT(CLONE_UNTRACED),
        NS_VALSTR_STRUCT(CLONE_CHILD_SETTID),
        NS_VALSTR_STRUCT(CLONE_NEWCGROUP),
        NS_VALSTR_STRUCT(CLONE_NEWUTS),
        NS_VALSTR_STRUCT(CLONE_NEWIPC),
        NS_VALSTR_STRUCT(CLONE_NEWUSER),
        NS_VALSTR_STRUCT(CLONE_NEWPID),
        NS_VALSTR_STRUCT(CLONE_NEWNET),
        NS_VALSTR_STRUCT(CLONE_IO),
    };

    memset(g_flags_to_str_res, 0, SUBPROC_STR_MAX);
    size_t offset = 0;

    uint64_t knownFlagMask = 0;
    size_t array_szie = ARR_SZ(cloneFlags);
    for (size_t i = 0; i < array_szie; ++i) {
        if (flags & cloneFlags[i].flag) {
            if (offset != 0) {
                offset += snprintf(g_flags_to_str_res + offset, SUBPROC_STR_MAX - 1 - offset, "%s", "|");
            }
            offset += snprintf(g_flags_to_str_res + offset, sizeof(res) - 1 - offset, "%s", cloneFlags[i]);
        }
        knownFlagMask |= cloneFlags[i].flag;
    }

    if (flags & ~(knownFlagMask)) {
        utilStrAppend(g_flags_to_str_res, offset, SUBPROC_STR_MAX, "|%#tx", flags & ~(knownFlagMask));
    }
    return g_flags_to_str_res;
}

/* Reset the execution environment for the new process */
static bool resetEnv(void)
{
    for (size_t i = 0; i < ARR_SZ(nssigs); i++) {
        if (signal(nssigs[i], SIG_DFL) == SIG_ERR) {
            return false;
        }
    }

    sigset_t sset;
    sigempty(&sset);
    if (sigprocmask(SIG_SETMASK, &sset, NULL) == -1) {
        return false;
    }

    return true;
}

// static char *concatArgs(char *const *argv)
// {
//     char *ret = NULL;

// }

static const char kSubprocErrorChar = 'E';
static const char kSubprocDoneChar = 'D';

static size_t appendArgv(char **argv, size_t argc, char *arg)
{
    if (argc >= ARG_ARRAY_MAX) {
        printf("argv too large, a maximum of %zu arguments is supported", (size_t)ARG_ARRAY_MAX);
        return -1;
    }
    argv[argc] = arg;
    return argc + 1;
}

static void newProc(nsjconf_t *nsjconf, int fd_in, int fd_out, int fd_err, int pipefd)
{
    if (!setup_fd(nsjconf, fd_in, fd_out, fd_err)) {
        return;
    }

    if (!resetEnv()) {
        return;
    }

    if (pipefd == -1) {
        if (userInitNsFromParent(nsjconf, getpid())) {
            return;
        }
        if (nsjconf->use_cgroupv2) {
            if (cgroupv2InitNsFromParent(nsjconf, getpid())) {
                return;
            }
        } else if (cgroupv1InitNsFromParent(nsjconf, getpid())) {
            return;
        }
    } else {
        char doneChar;
        if (utilReadFromFd(pipefd, &doneChar, sizeof(doneChar)) != sizeof(doneChar)) {
            return;
        } else if (doneChar != kSubprocDoneChar) {
            return;
        }
    }

    if (!containContainProc(nsjconf)) {
        return;
    }

    if (!nsjconf->keep_env) {
        clearenv();
    }
    // 手动设置运行环境
    for (char **env = nsjconf->envp, *env != NULL; ++env) {
        putenv(*env);
    }

    char *argv[ARG_ARRAY_MAX];
    size_t argc = 0;

    for (char *const *arg = nsjconf->argv; *arg != NULL; ++arg) {
        argc = appendArgv(argv, argc, *arg);
    }
    argv[argc] = NULL;

    if (nsjconf->use_execveat) {
#if defined(__NR_execveat)
        syscall(__NR_execveat, nsjconf->exec_fd, (uintptr_t) "", argv, (uintptr_t)environ, AT_EMPTY_PATH);
#else
        printf("Your system doesn't support execveat() syscall.\n");
        return;
#endif
    } else {
        execv(nsjconf->exec_file, argv);
    }

    printf("execv('%s') failed\n", nsjconf->exec_file);
}

static uint8_t clone_stack[128 * 1024] __attribute__((aligned(__BIGGEST_ALIGNMENT__)));
static __thread jmp_buf env;

static int cloneFunc(void *arg __attribute__((unused)))
{
    longjmp(env, 1);
    return 0;
}

pid_t subprocCloneProc(uintptr_t flags, int exit_signal)
{
    exit_signal &= CSIGNAL;

    if (flags & CLONE_VM) {
        printf("Cannot use clone(flags & CLONE_VM)\n");
        return -1;
    }

    if (flags & CLONE_NEWTIME) {
        printf("CLONE_NEWTIME requested, but it is only supported with the unshare() mode\n");
    }

#if defined(__NR_clone3)
    struct clone_args ca = {};
    ca.flags = (uint64_t)flags;
    ca.exit_signal = (uint64_t)exit_signal;

    pid_t ret = syscall(__NR_clone3, (uintptr_t)&ca, sizeof(ca));
    if (ret != -1 || errno != ENOSYS) {
        return ret;
    }
#endif /* defined(__NR_clone3) */

    if (flags & CLONE_NEWTIME) {
        printf("CLONE_NEWTIME was requested but clone3() is not support\n");
        return -1;
    }

    if (setjmp(env) == 0) {
        printf("Cloning process with flags:0x%x\n", flags);
        void *stack = &clone_stack[sizeof(clone_stack) / 2];
        return clone(cloneFunc, stack, flags | exit_signal, NULL, NULL, NULL);
    }
    // child
    return 0;
}

static bool initParent(nsjconf_t *nsjconf, pid_t pid, int pipefd)
{
    if (nsjconf->use_cgroupv2) {
        if (!cgroupv2InitNsFromParent(nsjconf, pid)) {
            exit(0xff);
        }
    } else if (!cgroupv1InitNsFromParent(nsjconf, pid)) {
        exit(0xff);
    }

    if (!userInitNsFromParent(nsjconf, pid)) {
        return false;
    }

    if (!utilWriteToFd(pipefd, &kSubprocDoneChar, sizeof(kSubprocDoneChar))) {
        return false;
    }

    return true;
}

pid_t subprocRunChild(nsjconf_t *nsjconf, int listen_fd, int fd_in, int fd_out, int fd_err)
{
    unsigned long flags = 0UL;
    flags |= (opts->clone_newnet ? CLONE_NEWNET : 0);
    flags |= (opts->clone_newuser ? CLONE_NEWUSER : 0);
    flags |= (opts->clone_newns ? CLONE_NEWNS : 0);
    flags |= (opts->clone_newpid ? CLONE_NEWPID : 0);
    flags |= (opts->clone_newipc ? CLONE_NEWIPC : 0);
    flags |= (opts->clone_newuts ? CLONE_NEWUTS : 0);
    flags |= (opts->clone_newcgroup ? CLONE_NEWCGROUP : 0);

    // use MODE_STANDALONE_ONECE

    printf("Creating new process with clone flags:0x%x and exit_signal: SIGCHLD\n", flags);

    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, sv) == -1) {
        printf("socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC) failed.\n");
        return -1;
    }

    int child_fd = sv[0];
    int parent_fd = sv[1];

    pid_t pid = subprocCloneProc(flags, SIGCHLD);

    if (pid == 0) {
        close(parent_fd);
        newProc(opts, fd_in, fd_out, fd_err, child_fd);
        write_to_fd(child_fd, &kSubprocErrorChar, sizeof(kSubprocErrorChar));
        printf("[ERROR] Lauching child process failed\n");
    }

    close(child_fd);

    if (pid == -1) {
        close(parent_fd);
        printf("pid == -1, errno:%s\n", strerror(errno));
        return pid;
    }

    // 记录子进程号，用于监控管理
    // add_proc(opts, pid);

    if (!initParent(opts, pid, parent_fd)) {
        close(parent_fd);
        return -1;
    }

    char rcv_char;
    size_t read_len = read_from_fd(parent_fd, &rcv_char, sizeof(rcv_char));
    if (read_len == 1 && rcv_char == kSubprocErrorChar) {
        close(parent_fd);
        return -1;
    }

    close(parent_fd);
    return pid;
}

int subprocSystemExe(const char *const char, char **env)
{
    bool exec_failed = false;
    const char *argv[];

    int sv[2];
    if (pipe2(sv, O_CLOEXEC) == -1) {
        PLOG_W("pipe2(sv, O_CLOEXEC)");
        return -1;
    }

    pid_t pid = fork();
    if (pid == -1) {
        PLOG_W("fork()");
        close(sv[0]);
        close(sv[1]);
        return -1;
    }

    if (pid == 0) {
        close(sv[0]);
        execve();
        PLOG_W("execve('%s')", argv[0]);
        utilWriteToFd(sv[1], "A", 1);
        exit(0);
    }

    close(sv[1]);
    char buf[1];
    if (utilReadFromFd(sv[0], buf, sizeof(buf)) > 0) {
        exec_failed = true;
        PLOGW("Couldn't execute '%s'", argv[0]);
    }
    close(sv[0]);

    for (;;) {
        int status;
        int ret = wait4(pid, &status, __WALL, NULL);
        if (ret ==-1 && errno == EINTR) {
            continue;
        }
        if (ret == -1) {
            PLOG_W("wait4(pid=%d)", pid);
            return -1;
        }
        if (WIFEXITED(status)) {
            int exit_code =WEXITSTATUS(status);
			LOG_D("pid=%d exited with exit code: %d", pid, exit_code);
            if (exec_failed) {
                return -1;
            } else  if (exit_code == 0) {
                return 0;
            } else {
                return 1;
            }
        }
        if (WIFSIGNALED(status)) {
            int exit_signal = WTERMSIG(status);
            LOG_W("pid=%d killed by signal: %d (%s)", pid, exit_signal, utilSigName(exit_signal));
            return 2;
        }
        PLOG_W("Unknown exit status: %d", status);
    }
}