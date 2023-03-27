#define _GNU_SOURCE
#include <inttypes.h>
#include <sched.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <memory.h>

#include "nsj_cpu.h"
#include "nsj_logs.h"
#include "nsj_util.h"

bool cpuInit(nsjconf_t *nsjconf)
{
    if (nsjconf->max_cpus == 0) {
        return false;
    }

    cpu_set_t *orig_mask = malloc(sizeof(cpu_set_t));

    if (sched_getaffinity(0, CPU_ALLOC_SIZE(CPU_SETSIZE), orig_mask) == -1) {
        
    }
}