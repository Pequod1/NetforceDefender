#!/bin/bash

echo '[*] Regenerating SSH keys'
rm -v /etc/ssh/ssh_host_*
dpkg-reconfigure openssh-server
echo '[*] Done'
exit 0
