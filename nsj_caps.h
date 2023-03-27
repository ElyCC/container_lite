#ifndef NSJ_CAPS_H
#define NSJ_CAPS_H

#include <stdbool.h>
#include <stdint.h>

#include "nsj_nsjail.h"

int capsNameToVal(const char *name);
int capsInitNs(nsjconf_t *nsjconf);

#endif /* NSJ_CAPS_H */