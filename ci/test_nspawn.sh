#!/bin/bash





sudo debootstrap stable /stable-chroot http://deb.debian.org/debian/
sdns="sudo systemd-nspawn -q --bind-ro /var/run/nscd/socket:/var/run/nscd/socket -D /stable-chroot"

# required for netgroup and innetgr
${sdns} apt-get update
${sdns} apt-get install ng-utils

rc=0

sudo useradd nsncdtest 
echo -e "foo1\t65000/tcp" | sudo tee -a /etc/services
echo -e "foo1\t65000/udp" | sudo tee -a /etc/services
echo "trusted-machines (machine1,user1,domain1), (machine2,user2,domain2), (machine3,user3,domain3)\n" | sudo tee -a /etc/netgroup

sudo dpkg -i nsncd*.deb

${sdns} getent passwd nsncdtest || rc=1
${sdns} getent group nsncdtest || rc=1
for i in $(seq 1 20); do
	${sdns} getent services 65000 || rc=1
	${sdns} getent services 65000/tcp || rc=1
	${sdns} getent services 65000/udp || rc=1
	${sdns} getent services foo1/tcp || rc=1
	${sdns} getent services foo1/udp || rc=1
	${sdns} netgroup trusted-machines || rc=1
	${sdns} getent netgroup trusted-machines || rc=1
	${sdns} innetgr -h machine1 trusted-machines || rc=1
	${sdns} innetgr -u user1 trusted-machines || rc=1
	${sdns} innetgr -d domain1 trusted-machines || rc=1
	${sdns} innetgr -h machine1 -u user1 -d domain1 trusted-machines || rc=1
done

exit ${rc}
