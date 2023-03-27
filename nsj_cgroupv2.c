#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "nsj_cgroupv2.h"
#include "nsj_nsjail.h"
#include "nsj_util.h"

#define CGROUP_PATH_MAX 256
#define STR_NORMAL 64

// [OPTI] 避免内存泄漏
char g_cgroupv2_path[CGROUP_PATH_MAX] = {0};

static char *getCgroupv2Path(nsjconf_t *nsjconf, pid_t pid)
{
    snprintf(g_cgroupv2_path, CGROUP_PATH_MAX - 1, "%s/NSJAIL.%d", nsjconf->cgroupv2_mount, pid);
    return g_cgroupv2_path;
}

static bool createCgroupv2(char *cgroupv2_path, pid_t pid)
{
    LOG_D("Create '%s' for pid=%d", cgroupv2_path, (int)pid);
    if (mkdir(cgroupv2_path, 0700) == -1 && errno != EEXIST) {
        PLOG_W("mkdir('%s', 0700) failed", cgroupv2_path);
        return false;
    }
    return true;
}

static bool writeToCgroupv2(char *cgroupv2_path, char *resource, char *value)
{
    if (cgroupv2_path == NULL || resource == NULL || value == NULL) {
        return false;
    }
    LOG_I("Setting '%s' to '%s'", resource, value);

    char resource_path[CGROUP_PATH_MAX] = {0};
    snprintf(resource_path, sizeof(resource_path) - 1, "%s/%s", cgroupv2_path, resource);
    if (!utilWriteBufToFile(resource_path, value, strlen(value), O_WRONLY)) {
        PLOG_W("Could not update %s", resource);
        return false;
    }
    return true;
}

static bool addPidToProcList(char *cgroupv2_path, pid_t pid)
{
    char pid_str[STR_NORMAL] = {0};
    snprintf(pid_str, sizeof(pid_str) - 1, "%d", pid);

	LOG_D("Adding pid='%s' to cgroup.procs", pid_str);

    char procs_path[CGROUP_PATH_MAX] = {0};
    snprintf(procs_path, sizeof(procs_path) - 1, "%s/cgroup.procs", cgroupv2_path);

    if (!utilWriteBufToFile(procs_path, pid_str, strlen(pid_str), O_WRONLY)) {
		PLOG_W("Could not update cgroup.procs");
        return false;
    }
    return true;
}

static void removeCgroupv2(char *cgroupv2_path)
{
	LOG_D("Remove '%s'", cgroupv2_path);
    if (rmdir(cgroupv2_path) == -1) {
		PLOG_W("rmdir('%s') failed", cgroupv2_path);
    }
}

static bool initNsFromParentMem(nsjconf_t *nsjconf, pid_t pid)
{
    ssize_t swap_max = nsjconf->cgroup_mem_swap_max;
    if (nsjconf->cgroup_mem_memsw_max > (size_t)0) {
        swap_max = nsjconf->cgroup_mem_memsw_max - nsjconf->cgroup_mem_max;
    }

    if (nsjconf->cgroup_mem_max == (size_t)0 && swap_max < (ssize_t)0) {
        return true;
    }

    char *cgroupv2_path = getCgroupv2Path(nsjconf, pid);

    RETURN_ON_FAILURE(createCgroupv2(cgroupv2_path, pid));
    RETURN_ON_FAILURE(addPidToProcList(cgroupv2_path, pid));

    char mem_max[STR_NORMAL] = {0};
    char mem_swap_max[STR_NORMAL] = {0};
    snprintf(mem_max, sizeof(mem_max) - 1, "%d", nsjconf->cgroup_mem_max);
    snprintf(mem_swap_max, sizeof(mem_swap_max) - 1, "%d", swap_max);

    RETURN_ON_FAILURE(writeToCgroup(cgroupv2_path, "memory.max", mem_max));
    RETURN_ON_FAILURE(writeToCgroup(cgroupv2_path, "memory.swap.max", mem_swap_max));

    return true;
}

static bool initNsFromParentPids(nsjconf_t *nsjconf, pid_t pid)
{
    if (nsjconf->cgroup_pids_max == 0U) {
        return true;
    }
    char *cgroupv2_path = getCgroupv2Path(nsjconf, pid);
    RETURN_ON_FAILURE(createCgroup(cgroupv2_path, pid));
    RETURN_ON_FAILURE(addPidToProcList(cgroupv2_path, pid));

    char pids_max[STR_NORMAL] = {0};
    snprintf(pids_max, sizeof(pids_max) - 1, "%d", nsjconf->cgroup_pids_max);
    RETURN_ON_FAILURE(writeToCgroup(cgroupv2_path, "pids.max", pids_max));

    return true;
}

static bool initNsFromParentCpu(nsjconf_t *nsjconf, pid_t pid)
{
    if (nsjconf->cgroup_cpu_ms_per_sec == 0U) {
        return true;
    }

    char *cgroupv2_path = getCgroupv2Path(nsjconf, pid);
    RETURN_ON_FAILURE(createCgroup(cgroupv2_path, pid));
    RETURN_ON_FAILURE(addPidToProcList(cgroupv2_path, pid));

    // The maximum bandwidth limit in the format: `$MAX $PERIOD`.
    // This indicates that the group may consume up to $MAX in each $PERIOD
    // duration.
    char cpu_ms_per_sec_str[STR_NORMAL] = {0};
    snprintf(cpu_ms_per_sec_str, sizeof(cpu_ms_per_sec_str) - 1, "%d 1000000", nsjconf->cgroup_cpu_ms_per_sec * 1000U);

    RETURN_ON_FAILURE(writeToCgroup(cgroupv2_path, "cpu.max", cpu_ms_per_sec_str));

    return true;
}

bool cgroupv2InitNsFromParent(nsjconf_t *nsjconf, pid_t pid)
{
    RETURN_ON_FAILURE(initNsFromParentMem(nsjconf, pid));
    RETURN_ON_FAILURE(initNsFromParentPids(nsjconf, pid));
    return initNsFromParentCpu(nsjconf, pid);
}

void cgroupv2FinishFromParent(nsjconf_t *nsjconf, pid_t pid)
{
    if (nsjconf->cgroup_mem_max != (size_t)0 || nsjconf->cgroup_pids_max != 0U ||
        nsjconf->cgroup_cpu_ms_per_sec != 0U) {
        removeCgroupv2(getCgroupv2Path(nsjconf, pid));
    }
}

bool cgroupv2InitNs()
{
    return true;
}