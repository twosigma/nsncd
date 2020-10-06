#include <sys/prctl.h>
#include <sys/types.h>
#include <errno.h>
#include <nss.h>
#include <pwd.h>
#include <string.h>

enum nss_status
_nss_whatami_getpwnam_r(const char *name, struct passwd *result, char *buffer, size_t buflen, int *errnop)
{
	if (strcmp(name, "whatami") == 0) {
		if (buflen < 16) {
			*errnop = ERANGE;
			return NSS_STATUS_TRYAGAIN;
		}
		prctl(PR_GET_NAME, buffer);
		result->pw_name = "whatami";
		result->pw_passwd = "*";
		result->pw_uid = 65534;
		result->pw_gid = 65534;
		result->pw_gecos = buffer;
		result->pw_dir = "/";
		result->pw_shell = "/sbin/nologin";
		return NSS_STATUS_SUCCESS;
	} else {
		return NSS_STATUS_NOTFOUND;
	}
}
