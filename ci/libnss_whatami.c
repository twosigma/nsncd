/*
 * Copyright 2020 Two Sigma Open Source, LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

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
