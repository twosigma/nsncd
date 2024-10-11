#!/bin/bash

sudo debootstrap stable /stable-chroot http://deb.debian.org/debian/
sudo dpkg -i nsncd*.deb	

sdns="sudo systemd-nspawn --quiet --no-pager --bind-ro /var/run/nscd/socket:/var/run/nscd/socket -D /stable-chroot"

# Install the tooling required for netgroup and innetgr
# Ensure nsswitch knows to read files for netgroup
${sdns} apt-get update
${sdns} apt-get install ng-utils
${sdns} sed '/netgroup/d' -i /etc/nsswitch.conf
${sdns} sed '$ a netgroup: files' -i /etc/nsswitch.conf

# Similar nsswitch config for the host system so nsncd can access our test data
sudo sed '/netgroup/d' -i /etc/nsswitch.conf
sudo sed '$ a netgroup: files' -i /etc/nsswitch.conf

rc=0

sudo useradd nsncdtest 
echo -e "foo1\t65000/tcp" | sudo tee -a /etc/services
echo -e "foo1\t65000/udp" | sudo tee -a /etc/services
echo -e "trusted-machines (machine1,user1,domain1), (machine2,user2,domain2), (machine3,user3,domain3)\n" | sudo tee -a /etc/netgroup

# copy in and execute tests inside the chroot
sudo cp ci/test_nsncd.sh /stable-chroot/
sudo chmod a+x /stable-chroot/test_nsncd.sh
${sdns} /test_nsncd.sh

