#!/bin/bash


sudo dpkg -i nsncd*.deb

sudo useradd nsncdtest 


sudo debootstrap --variant=minbase stable /stable-chroot http://deb.debian.org/debian/
sdns="sudo systemd-nspawn -q --bind-ro /var/run/nscd/socket:/var/run/nscd/socket -D /stable-chroot"

rc=0

${sdns} getent passwd nsncdtest || rc=1
${sdns} getent group nsncdtest || rc=1

exit ${rc}
