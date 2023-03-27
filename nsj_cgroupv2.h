#ifndef NSJ_CGROUPV2_H
#define NSJ_CGROUPV2_H

#include <stdbool.h>
#include <stddef.h>

#include "nsjail.h"


bool cgroupv2InitNsFromParent(nsjconf_t* nsjconf, pid_t pid);
void cgroupv2FinishFromParent(nsjconf_t* nsjconf, pid_t pid);
bool cgroupv2InitNs(void);

#endif /* NSJ_CGROUPV2_H */