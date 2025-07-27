#!/bin/bash

sudo debootstrap stable /stable-chroot http://deb.debian.org/debian/ &> /dev/null
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
cp /etc/services ./services
cp /etc/hosts ./hosts

echo -e "1.2.3.4\tfoo.localdomain\tfoo" >> hosts
sudo mv hosts /etc/hosts

# simple service lookups
echo -e "foo1\t65000/tcp" >> services
echo -e "foo1\t65000/udp" >> services
# huge service lookup to exercise buffer resize
echo -en "bufresize\t65001/tcp " >> services
for i in $(seq 1000); do echo -n "alias${i} "; done >> services
echo "" >> services
sudo mv services /etc/services

tail -5 /etc/services
echo -e "trusted-machines (machine1,user1,domain1), (machine2,user2,domain2), (machine3,user3,domain3)\n" | sudo tee -a /etc/netgroup

# copy in and execute tests inside the chroot
sudo cp ci/test_nsncd.sh /stable-chroot/
sudo chmod a+x /stable-chroot/test_nsncd.sh
${sdns} /test_nsncd.sh

