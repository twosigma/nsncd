#!/bin/bash -x


sudo debootstrap stable /stable-chroot http://deb.debian.org/debian/
sudo dpkg -i nsncd*.deb
sleep 1  # Give it a moment to start up

sudo useradd nsncdtest 
echo "nsncdtest (machine1,,), (machine2,,), (machine3,,)" | sudo tee -a /etc/netgroup
echo -e "nsncdtest\t65000/tcp" | sudo tee -a /etc/services
echo -e "'nsncdtest\t65000/udp" | sudo tee -a /etc/services


sdns="sudo systemd-nspawn -q --bind-ro /var/run/nscd/socket:/var/run/nscd/socket -D /stable-chroot"

rc=0
${sdns} getent passwd nsncdtest || rc=1
${sdns} getent netgroup nsncdtest || rc=1
${sdns} getent services nsncdtest || rc=1
${sdns} getent services nsncdtest/tcp || rc=1
${sdns} getent services nsncdtest/udp || rc=1
${sdns} getent services 65000/tcp || rc=1
${sdns} getent services 65000/udp || rc=1

exit ${rc}
