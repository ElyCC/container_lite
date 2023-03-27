#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "nsj_cgroupv1.h"
#include "nsj_logs.h"
#include "nsj_nsjail.h"
#include "nsj_util.h"

#define CGROUP_PATH_MAX 256
#define STR_NORMAL 64

static bool createCgroup(char *cgroup_path, pid_t pid)
{
    if (cgroup_path == NULL) {
        return false;
    }

    LOG_D("Create %s for pid=%d", cgroup_path, pid);

    if (mkdir(cgroup_path, 0700) == -1 && errno != EEXIST) {
        PLOG_W("mkdir(%s, 0700) failed", cgroup_path);
        return false;
    }

    return true;
}

static bool writeToCgroup(const char *cgroup_path, char *value, char *what)
{
    if (cgroup_path == NULL || value == NULL || what == NULL) {
        return false;
    }
    LOG_D("Setting %s to '%s'", cgroup_path, value);

    if (!utilWriteBufToFile(cgroup_path, vaule, strlen(value), O_WRONLY | O_CLOEXEC)) {
        LOG_W("Could not update %s", what);
        return false;
    }

    return true;
}

static bool addPidToTaskList(char *cgroup_path, pid_t pid)
{
    char pid_str[STR_NORMAL] = {0};
    snprintf(pid_str, sizeof(pid_str) - 1, "%d", pid);
    char tasks_path[CGROUP_PATH_MAX] = {0};
    snprintf(tasks_path, sizeof(tasks_path) - 1, "%s/tasks", cgroup_path);
    LOG_D("Adding pid='%s' to %s", pid_str, tasks_path);
    return writeToCgroup(tasks_path, pid_str, "task list");
}

static bool initNsFromParentMem(nsjconf_t *nsjconf, pid_t pid)
{
    size_t memsw_max = nsjconf->cgroup_mem_memsw_max;
    if (nsjconf->cgroup_mem_swap_max >= (ssize_t)0) {
        memsw_max = nsjconf->cgroup_mem_swap_max + nsjconf->cgroup_mem_max;
    }

    if (nsjconf->cgroup_mem_max == (size_t)0 && memsw_max == (size_t)0) {
        return true;
    }

    char mem_cgroup_path[CGROUP_PATH_MAX] = {0};
    snprintf(mem_cgroup_path, sizeof(mem_cgroup_path) - 1, "%s/%s/NSJAIL.%d",
             nsjconf->cgroup_mem_mount, nsjconf->cgroup_mem_parent, pid);
    RETURN_ON_FAILURE(createCgroup(mem_cgroup_path, pid));

    char mem_cgroup_oom_cntl[CGROUP_PATH_MAX] = {0};
    snprintf(mem_cgroup_oom_cntl, sizeof(mem_cgroup_oom_cntl) - 1, "%s/memory.oom_control", mem_cgroup_path);
    RETURN_ON_FAILURE(writeToCgroup(mem_cgroup_oom_cntl, "0", "memory cgroup oom control"));

    char mem_cgroup_limit[CGROUP_PATH_MAX] = {0};
    snprintf(mem_cgroup_limit, sizeof(mem_cgroup_limit) - 1, "%s/memory.limit_in_bytes", mem_cgroup_path);
    char mem_max_str[STR_NORMAL] = {0};
    snprintf(mem_max_str, sizeof(mem_max_str) - 1, "%d", nsjconf->cgroup_mem_max);
    RETURN_ON_FAILURE(writeToCgroup(mem_cgroup_limit, mem_max_str, "memory cgroup max limit"));

    char mem_cgroup_memsw_limit[CGROUP_PATH_MAX] = {0};
    snprintf(mem_cgroup_memsw_limit, sizeof(mem_cgroup_memsw_limit) - 1, "%s/memory.memsw.limit-in_bytes",
             mem_cgroup_path);
    char mem_memsw_max_str[STR_NORMAL] = {0};
    snprintf(mem_memsw_max_str, sizeof(mem_memsw_max_str) - 1, "%d", memsw_max);
    RETURN_ON_FAILURE(writeToCgroup(mem_cgroup_memsw_limit, mem_memsw_max_str, "memory+Swap cgroup max limit"));

    return addPidToTaskList(mem_cgroup_path, pid);
}

static bool initNsFromParentPids(nsjconf_t *nsjconf, pid_t pid)
{
    if (nsjconf->cgroup_pids_max == 0U) {
        return true;
    }

    char pids_cgroup_path[CGROUP_PATH_MAX] = {0};
    snprintf(pids_cgroup_path, sizeof(pids_cgroup_path) - 1, "%s/%s/NSJAIL.%d",
             nsjconf->cgroup_pids_mount, nsjconf->cgroup_pids_parent, pid);
    RETURN_ON_FAILURE(createCgroup(pids_cgroup_path, pid));

    char pids_cgroup_max[CGROUP_PATH_MAX] = {0};
    snprintf(pids_cgroup_max, sizeof(pids_cgroup_max) - 1, "%s/pids.max", pids_cgroup_path);
    char pids_max_str[STR_NORMAL] = {0};
    snprintf(pids_max_str, sizeof(pids_max_str) - 1, "%d", nsjconf->cgroup_pids_max);
    RETURN_ON_FAILURE(writeToCgroup(pids_cgroup_max, pids_max_str, "pids cgroup max limit"));

    return addPidToTaskList(pids_cgroup_path, pid);
}

static bool initNsFromParentNetCls(nsjconf_t *nsjconf, pid_t pid)
{
    if (nsjconf->cgroup_net_cls_classid == 0U) {
        return true;
    }

    char net_cls_cgroup_path[CGROUP_PATH_MAX] = {0};
    snprintf(net_cls_cgroup_path, sizeof(net_cls_cgroup_path) - 1, "%s/%s/NSJAIL.%d",
             nsjconf->cgroup_net_cls_mount, nsjconf->cgroup_net_cls_parent, pid);
    RETURN_ON_FAILURE(createCgroup(net_cls_cgroup_path, pid));

    char net_cls_cgroup_classid[CGROUP_PATH_MAX] = {0};
    snprintf(net_cls_cgroup_classid, sizeof(net_cls_cgroup_classid) - 1, "%s/net_cls.classid", net_cls_cgroup_path);
    char net_cls_classid_str[STR_NORMAL] = {0};
    snprintf(net_cls_classid_str, sizeof(net_cls_classid_str) - 1, "0x%x", nsjconf->cgroup_net_cls_classid);
    RETURN_ON_FAILURE(writeToCgroup(net_cls_cgroup_classid, net_cls_classid_str, "net_cls cgroup classid"));

    return addPidToTaskList(net_cls_cgroup_path, pid);
}

static bool initNsFromParentCpu(nsjconf_t *nsjconf, pid_t pid)
{
    if (nsjconf->cgroup_cpu_ms_per_sec == 0UL) {
        return true;
    }

    char cpu_cgroup_path[CGROUP_PATH_MAX] = {0};
    snprintf(cpu_cgroup_path, sizeof(cpu_cgroup_path) - 1, "%s/%s/NSJAIL.%d",
             nsjconf->cgroup_cpu_mount, nsjconf->cgroup_cpu_parent, pid)
        RETURN_ON_FAILURE(createCgroup(cpu_cgroup_path, pid));

    char cpu_cgroup_cfs_period[CGROUP_PATH_MAX] = {0};
    snprintf(cpu_cgroup_cfs_period, sizeof(cpu_cgroup_cfs_period) - 1, "%s/cpu.cfs_period_us", cpu_cgroup_path);
    RETURN_ON_FAILURE(writeToCgroup(cpu_cgroup_cfs_period, "1000000", "cpu period"));

    char cpu_cgroup_cfs_quota[CGROUP_PATH_MAX] = {0};
    snprintf(cpu_cgroup_cfs_quota, sizeof(cpu_cgroup_cfs_quota) - 1, "%s/cpu.cfs_quota_us", cpu_cgroup_path);
    char cpu_ms_per_sec_str[STR_NORMAL] = {0};
    snprintf(cpu_ms_per_sec_str, sizeof(cpu_ms_per_sec_str) - 1, "%d", nsjconf->cgroup_cpu_ms_per_sec * 1000U);
    RETURN_ON_FAILURE(writeToCgroup(cpu_cgroup_cfs_quota, cpu_ms_per_sec_str, "cpu quota"));

    return addPidToTaskList(cpu_cgroup_path, pid);
}

bool cgroupv1InitFromParent(nsjconf_t *nsjconf, pid_t pid)
{
    RETURN_ON_FAILURE(initNsFromParentMem(nsjconf, pid));
    RETURN_ON_FAILURE(initNsFromParentPids(nsjconf, pid));
    RETURN_ON_FAILURE(initNsFromParentNetCls(nsjconf, pid));

    return initNsFromParentCpu(nsjconf, pid);
}

static removeCgroup(char *cgroup_path)
{
	LOG_D("Remove %s", cgroup_path);
    if (rmdir(cgroup_path) == -1) {
		PLOG_W("rmdir(%s) failed", cgroup_path);
    }
}

void cgroupv1FinishFromParent(nsjconf_t *nsjconf, pid_t pid)
{
    if (nsjconf->cgroup_mem_max != (size_t)0 || nsjconf->cgroup_mem_memsw_max != (size_t)0) {
        char mem_cgroup_path[CGROUP_PATH_MAX] = {0};
        snprintf(mem_cgroup_path, sizeof(mem_cgroup_path) - 1, "%s/%s/NSJAIL.%d",
                 nsjconf->cgroup_mem_mount, nsjconf->cgroup_mem_parent, pid);
        removeCgroup(mem_cgroup_path);
    }
    if (nsjconf->cgroup_pids_max != 0U) {
        char pids_cgroup_path[CGROUP_PATH_MAX] = {0};
        snprintf(pids_cgroup_path, sizeof(pids_cgroup_path) - 1, "%s/%s/NSJAIL.%d",
                 nsjconf->cgroup_pids_mount, nsjconf->cgroup_pids_parent, pid);
        removeCgroup(pids_cgroup_path);
    }
    if (nsjconf->cgroup_net_cls_classid != 0U) {
        char net_cls_cgroup_path[CGROUP_PATH_MAX] = {0};
        snprintf(net_cls_cgroup_path, sizeof(net_cls_cgroup_path) - 1, "%s/%s/NSJAIL.%d",
                 nsjconf->cgroup_net_cls_mount, nsjconf->cgroup_net_cls_parent, pid);
        removeCgroup(net_cls_cgroup_path);
    }
    if (nsjconf->cgroup_cpu_ms_per_sec != 0U) {
        char cpu_cgroup_path[CGROUP_PATH_MAX] = {0};
        snprintf(cpu_cgroup_path, sizeof(cpu_cgroup_path) - 1, "%s/%s/NSJAIL.%d",
                 nsjconf->cgroup_cpu_mount, nsjconf->cgroup_cpu_parent, pid)
            removeCgroup(cpu_cgroup_path);
    }
}

bool cgroupv1InitNs()
{
    return true;
}