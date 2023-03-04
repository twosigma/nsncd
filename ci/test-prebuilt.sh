#!/bin/sh

# Copyright 2023 Two Sigma Open Source, LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

set -ex

gcc -fPIC -shared -o ci/libnss_whatami.so.2 ci/libnss_whatami.c
sudo cp ci/libnss_whatami.so.2 /lib
sudo sed -i 's/\(passwd\|group\):/& whatami/' /etc/nsswitch.conf
sudo target/debug/nsncd &
NSNCD_PID=$!
getent passwd whatami | grep nsncd
getent initgroups am_i_nsncd | grep '100001.*100020'
kill ${NSNCD_PID}
