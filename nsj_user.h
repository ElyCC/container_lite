#ifndef NSJ_USER_H
#define NSJ_USER_H

#include <stdbool.h>
#include <string.h>

#include "nsj_nsjail.h"

bool userInitNsFromParent(nsjconf_t *nsjconf, pid_t pid);
bool userInitNsFromChild(nsjconf_t *nsjconf);
bool uerParseId(nsjconf_t *nsjconf, const char *i_id, const char *o_id, size_t cnt, bool is_gid, bool is newidmap);

#endif /* NSJ_USER_H */