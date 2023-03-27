#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <limits.h>
#include <linux/securebits.h>
#include <pwd.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>

#include <inttypes.h>

#include "nsj_logs.h"
#include "nsj_macros.h"
#include "nsj_subproc.h"
#include "nsj_user.h"
#include "nsj_util.h"

#define STR_(x) #x
#define STR(x) STR_(x)

char kNewUidPath[] =
#ifdef NEWUIDMAP_PATH
    STR(NEWUIDMAP_PATH);
#else
    "/user/bin/newuidmap";
#endif

char kNewGidPath[] =
#ifdef NEWGIDMAP_PATH
    STR(NEWGIDMAP_PATH);
#else
    "/user/bin/newgidmap";
#endif

static bool setResGid(gid_t gid)
{
    LOG_D("setresgid(%d)", gid);
#if defined(__NR_setresgid32)
    if (util::syscall(__NR_setresgid32, (uintptr_t)gid, (uintptr_t)gid, (uintptr_t)gid) == -1) {
        PLOG_W("setresgid32(%d)", (int)gid);
        return false;
    }
#else  /* defined(__NR_setresgid32) */
    if (util::syscall(__NR_setresgid, (uintptr_t)gid, (uintptr_t)gid, (uintptr_t)gid) == -1) {
        PLOG_W("setresgid(%d)", gid);
        return false;
    }
#endif /* defined(__NR_setresuid32) */
    return true;
}

static bool setResUid(uid_t uid)
{
    LOG_D("setresuid(%d)", uid);
#if defined(__NR_setresuid32)
    if (util::syscall(__NR_setresuid32, (uintptr_t)uid, (uintptr_t)uid, (uintptr_t)uid) == -1) {
        PLOG_W("setresuid32(%d)", (int)uid);
        return false;
    }
#else  /* defined(__NR_setresuid32) */
    if (util::syscall(__NR_setresuid, (uintptr_t)uid, (uintptr_t)uid, (uintptr_t)uid) == -1) {
        PLOG_W("setresuid(%d)", uid);
        return false;
    }
#endif /* defined(__NR_setresuid32) */
    return true;
}

static bool hasGidMapSelf(nsjconf_t *nsjconf)
{
    for (int i = 0; i < nsjconf->gids_index; ++i) {
        if (!nsjconf->gids[i].is_newidmap) {
            return true;
        }
    }
    return false;
}

static bool setGroupDeny(nsjconf_t *nsjconf, pid_t pid)
{
    if (!nsjconf->clone_newuser || nsjconf->orig_euid == 0 || !hasGidMapSelf(nsjconf)) {
        return true;
    }

    char fname[PATH_MAX] = {0};
    snprintf(fname, sizeof(fname) - 1, "proc/%d/setgroups", pid);
    const char *const denystr = "deny";
    if (!utilWriteBufToFile(fname, denystr, strlen(denystr), O_WRONLY | O_CLOEXEC)) {
        PLOG_E("utilWriteBufToFile('%s', '%s') failed", fname, denystr);
        return false;
    }
}

static bool uidMapSelf(nsjconf_t *nsjconf, pid_t pid)
{
    char map[256];
    uint32_t offset = 0;
    for (int i = 0; i < nsjconf->uids_index; ++i) {
        if (nsjconf->uids[i].is_newidmap) {
            continue;
        }
        offset += snprintf(map + offset, sizeof(map) - 1 - offset, "%d %d %d\n", nsjconf->uids[i].inside_id,
                           nsjconf->uids[i].outside_id, nsjconf->uids[i].count);
    }
    if (offset == 0) {
        return true;
    }

    char fname[PATH_MAX];
    snprintf(fname, sizeof(fname), "/proc/%d/uid_map", pid);
    LOG_D("Writing '%s' to '%s'", map, fname);
    if (!utilWriteBufToFile(fname, map, strlen(map), O_WRONLY | O_CLOEXEC)) {
        LOG_E("utilWriteBufToFile('%s', '%s') failed", fname, map);
        return false;
    }

    return true;
}

static bool gidMapSelf(nsjconf_t *nsjconf, pid_t pid)
{
    char map[256];
    uint32_t offset = 0;
    for (int i = 0; i < nsjconf->gids_index; ++i) {
        if (nsjconf->gids[i].is_newidmap) {
            continue;
        }
        offset += snprintf(map + offset, sizeof(map) - 1 - offset, "%d %d %d\n", nsjconf->gids[i].inside_id,
                           nsjconf->gids[i].outside_id, nsjconf->gids[i].count);
    }
    if (offset == 0) {
        return true;
    }

    char fname[PATH_MAX];
    snprintf(fname, sizeof(fname), "/proc/%d/gid_map", pid);
    LOG_D("Writing '%s' to '%s'", map, fname);
    if (!utilWriteBufToFile(fname, map, strlen(map), O_WRONLY | O_CLOEXEC)) {
        LOG_E("utilWriteBufToFile('%s', '%s') failed", fname, map);
        return false;
    }

    return true;
}

/* Use newgidmap for writing the gid map */
static bool gidMapExternal(nsjconf_t *nsjconf, pid_t pid)
{
    bool use = false;
    // FIXME big enough
    char argv[32][64] = {0};
    argv[0] = kNewUidPath;
    sprintf(argv[1], "%d", pid);
    uint8_t offset = 2;
    for (int i = 0; i < nsjconf->gids_index; ++i) {
        if (!nsjconf->gids[i].is_newidmap) {
            continue;
        }
        use = true;

        sprintf(arg[offset++], "%d", nsjconf->gids[i].inside_id);
        sprintf(arg[offset++], "%d", nsjconf->gids[i].outside_id);
        sprintf(arg[offset++], "%d", nsjconf->gids[i].count);
    }
    if (!use) {
        return true;
    }
    if (subprocSystemExe(argv, environ) != 0) {
        LOG_E("'%s' failed", kNewGidPath);
        return false;
    }

    return true;
}

/* Use newuidmap for writing the uid map */
static bool uidMapExternal(nsjconf_t *nsjconf, pid_t pid)
{
    bool use = false;

    char argv[32][64] = {0};
    argv[0] = kNewUidPath;
    sprintf(argv[1], "%d", pid);
    uint8_t offset = 2;
    for (int i = 0; i < nsjconf->uids_index; ++i) {
        if (!nsjconf->uids[i].is_newidmap) {
            continue;
        }
        use = true;

        sprintf(arg[offset++], "%d", nsjconf->uids[i].inside_id);
        sprintf(arg[offset++], "%d", nsjconf->uids[i].outside_id);
        sprintf(arg[offset++], "%d", nsjconf->uids[i].count);
    }
    if (!use) {
        return true;
    }
    if (subprocSystemExe(argv, environ) != 0) {
        LOG_E("'%s' failed", kNewGidPath);
        return false;
    }

    return true;
}

static bool uidGidMap(nsjconf_t *nsjconf, pid_t pid)
{
    RETURN_ON_FAILURE(gidMapSelf(nsjconf, pid));
    RETURN_ON_FAILURE(gidMapExternal(nsjconf, pid));
    RETURN_ON_FAILURE(uidMapSelf(nsjconf, pid));
    RETURN_ON_FAILURE(uidMapExternal(nsjconf, pid));

    return true;
}

bool userInitNsFromParent(nsjconf_t *nsjconf, pid_t pid)
{
    if (!setGroupsDeny(nsjconf, pid)) {
        return false;
    }
    if (!nsjconf->clone_newuser) {
        return true;
    }
    if (!uidGidMap(nsjconf, pid)) {
        return false;
    }
    return true;
}

bool userInitNsChild(nsjconf_t *nsjconf)
{
    if (!nsjconf->clone_newuser && nsjconf->orig_euid != 0) {
        return true;
    }

    if (prctl(PR_SET_SECUREBITS, SECBIT_KEEP_CAPS | SECBIT_NO_SETUID_FIXUP, 0UL, 0UL, 0UL) == -1) {
        PLOG_E("prctl(PR_SET_SECUREBITS, SECBIT_KEEP_CAPS | SECBIT_NO_SETUID_FIXUP)");
        return false;
    }

    gid_t groups[MAX_USER_MAPPING];
    uint32_t ngroups = 0;
    //  for debug
    char group_str[256] = {0};
    uint32_t offset = 0;

    offset += snprintf(group_str + offset, sizeof(group_str) - 1 - offset, "%s", "[");
    if (!nsjconf->clone_newuser && nsjconf->gids_index > 1) {
        for (int i = 0; i < nsjconf->gids_index; i++) {
            groups[i] = nsjconf->gids[i].inside_id;
            offset += snprintf(group_str + offset, sizeof(group_str) - 1 - offset, "%d", groups[i]);
            if (i < nsjconf->gids_index - 1) {
                offset += snprintf(group_str + offset, sizeof(group_str) - 1 - offset, "%s", ", ");
            }
        }
    }
    offset += snprintf(group_str + offset, sizeof(group_str) - 1 - offset, "%s", "]");

    if (!setResGid(nsjconf->gids[0].inside_id)) {
        PLOG_E("setresgid(%lu)", (unsigned long)nsjconf->gids[0].inside_id);
        return false;
    }

    LOG_D("setgroups(%zu, %s)", ngroups, groupsString.c_str());
    if (setgroups(ngroups, groups) == -1) {
        /* Indicate error if specific groups were requested */
        if (ngroups > 0) {
            PLOG_E("setgroups(%zu, %s) failed", ngroups, group_str);
            return false;
        }
        PLOG_D("setgroups(%zu, %s) failed", ngroups, group_str);
    }

    if (!setResUid(nsjconf->uids[0].inside_id)) {
        PLOG_E("setresuid(%lu)", (unsigned long)nsjconf->uids[0].inside_id);
        return false;
    }

    if (prctl(PR_SET_SECUREBITS, 0UL, 0UL, 0UL, 0UL) == -1) {
        PLOG_E("prctl(PR_SET_SECUREBITS, 0)");
        return false;
    }

    return true;
}

static uid_t parseUid(const char *id)
{
    if (id == NULL) {
        return getuid();
    }
    struct passwd *pw = getpwnam(id);
    if (pw != NULL) {
        return pw->pw_uid;
    }
    if (utilIsANumber(id.c_str())) {
        return (uid_t)strtoimax(id, NULL, 0);
    }
    return (uid_t)-1;
}

static gid_t parseGid(const char *id)
{
    if (id == NULL) {
        return getgid();
    }
    struct group *gr = getgrnam(id);
    if (gr != NULL) {
        return gr->gr_gid;
    }
    if (utilIsANumber(id) {
        return (gid_t)strtoimax(id, NULL, 0);
    }
    return (gid_t)-1;
}

// 输入g/uid解析
bool userParseId(nsjconf_t *nsjconf, const char *i_id, const char *o_id, size_t cnt, bool is_gid, bool is_newidmap)
{
    if (cnt < 1) {
        cnt = 1;
    }

    uid_t inside_id;
    uid_t outside_id;

    if (is_gid) {
        inside_id = parseGid(i_id);
        if (inside_id == (uid_t)-1) {
            PLOG_W("Cannot parse '%s' as GID", i_id);
            return false;
        }
        outside_id = parseGid(o_id);
        if (outside_id == (uid_t)-1) {
            PLOG_W("Cannot parse '%s' as GID", o_id);
            return false;
        }
    } else {
        inside_id = parseUid(i_id);
        if (inside_id == (uid_t)-1) {
            PLOG_W("Cannot parse '%s' as UID", i_id);
            return false;
        }
        outside_id = parseUid(o_id);
        if (outside_id == (uid_t)-1) {
            PLOG_W("Cannot parse '%s' as UID", o_id);
            return false;
        }
    }

    struct idmap_t id;
    id.inside_id = inside_id;
    id.outside_id = outside_id;
    id.count = cnt;
    id.is_newidmap = is_newidmap;

    if (is_gid) {
        memcpy(&(nsjconf->gids[(nsjconf->gids_index)++]), &id, sizeof(struct idmap_t));
    } else {
        memcpy(&(nsjconf->uids[(nsjconf->uids_index)++]), &id, sizeof(struct idmap_t));
    }

    return true;
}
