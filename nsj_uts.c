#include <string.h>
#include <unistd.h>

#include "nsj_logs.h"
#include "nsj_nsjail.h"

bool initNs(nsjconf_t* nsjconf) {
	if (!nsjconf->clone_newuts) {
		return true;
	}

	LOG_D("Setting hostname to '%s'", nsjconf->hostname);
	if (sethostname(nsjconf->hostname, strlen(nsjconf->hostname)) == -1) {
		PLOG_E("sethostname('%s')", nsjconf->hostname);
		return false;
	}
	return true;
}