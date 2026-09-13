#!/bin/bash -e

# this script tests sample calls inside a container
# nsncd has to be running outside, with suitable test data configured

rc=0

# basic lookups
getent passwd nsncdtest || rc=1
getent passwd 2709991565 || rc=1
getent group nsncdtest || rc=1
getent group 2709991565 || rc=1
id bug72 | grep 2709991565 || rc=1
getent initgroups bug72 | grep 2709991565 || rc=1
getent initgroups bug72 | grep 2709991566 || rc=1
# we expect all of these to succeed 
for i in $(seq 1 100); do
	getent services 65000 || rc=1
	getent services 65000/tcp || rc=1
	getent services 65000/udp || rc=1
	getent services foo1/tcp || rc=1
	getent services foo1/udp || rc=1
        getent services bufresize/tcp > /dev/null|| rc=1
	netgroup trusted-machines || rc=1
	getent netgroup trusted-machines || rc=1
	innetgr -h machine1 trusted-machines || rc=1
	innetgr -u user1 trusted-machines || rc=1
	innetgr -d domain1 trusted-machines || rc=1
	innetgr -h machine1 -u user1 -d domain1 trusted-machines || rc=1
	# ipv4 host lookups reverse and forward
	getent hosts 1.2.3.4 || rc=1
	getent hosts foo.localdomain || rc=1
	# ipv6 host lookups reverse and forward
	getent hosts ::1 || rc=1
	getent hosts fd00::1234 || rc=1
	getent hosts foo6.localdomain || rc=1
	# getai (getaddrinfo) exercise address families
	getent ahosts foo.localdomain || rc=1
	getent ahostsv4 foo.localdomain || rc=1
	getent ahostsv6 foo6.localdomain || rc=1
done

exit ${rc}
