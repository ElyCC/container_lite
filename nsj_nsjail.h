#ifndef NSJ_NSJAIL_H
#define NSJ_NSJAIL_H

#include <linux/filter.h>
#include <netinet/ip6.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <time.h>
#include <unistd.h>

static const int nssigs[] = {
    SIGINT,
    SIGQUIT,
    SIGUSR1,
    SIGALRM,
    SIGCHLD,
    SIGTERM,
    SIGTTIN,
    SIGTTOU,
    SIGPIPE,
};

struct pids_t {
    time_t start;
    char *remote_txt;
    struct sockaddr_in6 remote_addr;
    int pid_syscall_fd;
};

struct mount_t {
    char *src;
    char *src_content;
    char *dst;
    char *fs_type;
    char *options;
    uintptr_t flags;
    bool is_dir;
    bool is_syslink;
    bool is_mandatory;
    bool mounted;
};

struct idmap_t {
    uid_t inside_id;
    uid_t outside_id;
    size_t count;
    bool is_newidmap;
};

enum ns_mode_t {
    MODE_LISTEN_TCP = 0,
    MODE_STANDALONE_ONCE,
    MODE_STANDALONE_EXECVE,
    MODE_STANDALONE_RERUN
};

enum {
    MAX_MOUNT = 4096,
    MAX_IFACES = 4096,
    MAX_USER_MAPPING = 340, /* as of linux 4.15, c.f. user_namespaces(7) */
    MAX_OPEN_FDS = 16,
    MAX_CAPS = 16,
    MAX_PIPES = 8,
};

struct pipemap_t {
    int sock_fd;
    int pipe_in;
    int pipe_out;
    pid_t pid;
    bool unknown;
};

typedef struct {
    char *exec_file;
    bool use_execveat;
    int exec_fd;

    char *hostname;
    char *cwd;
    char *chroot;
    int port;
    char *bindhost;
    bool daemonize;
    uint64_t tlimit;
    size_t max_cpus;
    bool keep_env;
    bool keep_caps;
    bool disable_no_new_privs;

    uint64_t rl_as;
    uint64_t rl_core;
    uint64_t rl_cpu;
    uint64_t rl_fsize;
    uint64_t rl_nofile;
    uint64_t rl_nproc;
    uint64_t rl_stack;
    uint64_t rl_mlock;
    uint64_t rl_rtpr;
    uint64_t rl_msgq;

    bool disable_rl;
    unsigned long personality;

    bool clone_newnet;
    bool clone_newuser;
    bool clone_newns;
    bool no_pivotroot;
    bool clone_newpid;
    bool clone_newipc;
    bool clone_newuts;
    bool clone_newcgroup;
    bool clone_newtime;

    enum ns_mode_t mode;
    bool is_root_rw;
    bool is_silent;
    bool stderr_to_null;
    bool skip_setsid;
    unsigned int max_conns;
    unsigned int max_conns_per_ip;
    char *proc_path;
    bool is_proc_rw;

    bool iface_lo;
    char *iface_vs;
    char *iface_vs_ip;
    char *iface_vs_nm;
    char *iface_vs_gw;
    char *iface_vs_ma;
    char *iface_vs_mo;

    bool disable_tsc;
    bool forward_signals;

    char *cgroup_mem_mount;
    char *cgroup_mem_parent;
    size_t cgroup_mem_max;
    size_t cgroup_mem_memsw_max;
    ssize_t cgroup_mem_swap_max;
    char *cgroup_pids_mount;
    char *cgroup_pids_parent;
    unsigned int cgroup_pids_max;
    char *cgroup_net_cls_mount;
    char *cgroup_net_cls_parent;
    unsigned int cgroup_net_cls_classid;
    char *cgroup_cpu_mount;
    char *cgroup_cpu_parent;
    unsigned int cgroup_cpu_ms_per_sec;
    char *cgroupv2_mount;
    bool use_cgroupv2;

    char *kafel_file_path;
    char *kafel_string;
    struct sock_fprog seccomp_fprog;
    bool seccomp_log;
    int nice_level;

    uid_t orig_uid;
    uid_t orig_euid;

    char *const *argv;        // std::vector<std::string> argv;
    char *const *envs;        // std::vector<std::string> envs;
    char *ifaces[MAX_IFACES]; // std::vector<std::string> ifaces;

    struct mount_t mountpts[MAX_MOUNT]; // std::vector<mount_t> mountpts;
    uint8_t uids_index;
    struct idmap_t uids[MAX_USER_MAPPING]; // std::vector<idmap_t> uids;
    uint8_t gids_index;
    struct idmap_t gids[MAX_USER_MAPPING]; // std::vector<idmap_t> gids;
    struct pipemap_t pipes[MAX_PIPES];     // std::vector<pipemap_t> pipes;

    int openfds[MAX_OPEN_FDS]; // std::vector<int> openfds;
    int caps[MAX_CAPS];        // std::vector<int> caps;

    // std::map<pid_t, pids_t> pids;
} nsjconf_t;

#endif /* NSJ_NSJAIL_H */