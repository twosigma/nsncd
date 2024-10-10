#!/bin/bash


sudo dpkg -i nsncd*.deb



sudo debootstrap --variant=minbase stable /stable-chroot http://deb.debian.org/debian/
sdns="sudo systemd-nspawn -q --bind-ro /var/run/nscd/socket:/var/run/nscd/socket -D /stable-chroot"

rc=0

sudo useradd nsncdtest 
echo -e "foo1\t65000/tcp" | sudo tee -a /etc/services
echo -e "foo1\t65000/udp" | sudo tee -a /etc/services

${sdns} getent passwd nsncdtest || rc=1
${sdns} getent group nsncdtest || rc=1
for i in $(seq 1 20); do
	${sdns} getent services 65000 || rc=1
	${sdns} getent services 65000/tcp || rc=1
	${sdns} getent services 65000/udp || rc=1
	${sdns} getent services foo1/tcp || rc=1
	${sdns} getent services foo1/udp || rc=1
done

exit ${rc}
