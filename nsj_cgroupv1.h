#ifndef NSJ_CGROUPV1_H
#define NSJ_CGROUPV1_H

#include <stdbool.h>
#include <stddef.h>

#include "nsjail.h"

bool cgroupv1InitFromParent(nsjconf_t *nsjconf, pid_t pid);
void cgroupv1FinishFromParent(nsjconf_t *nsjconf, pid_t pid);
bool cgroupv1InitNs(void);

#endif /* NSJ_CGROUPV1_H */