#!/bin/sh

set -ex

debian/rules vendor
dpkg-buildpackage --no-sign
gcc -fPIC -shared -o ci/libnss_whatami.so.2 ci/libnss_whatami.c
sudo cp ci/libnss_whatami.so.2 /lib
sudo sed -i 's/passwd:/& whatami/' /etc/nsswitch.conf
sudo dpkg -i ../nsncd*.deb
getent passwd whatami | grep nsncd
