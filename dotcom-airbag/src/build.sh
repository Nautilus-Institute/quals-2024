#!/bin/bash

set -e

# We all make mistakes in life. My only mistake is building C applications
# with bash scripts.

make all
#gcc main.c -O2 -o challenge
#strip challenge

# Copy file so it can be used on the server
# It will end up in /opt/challenge
cp airbag dotcom_market ../build/.
cp bailout airbag dotcom_market dist/.
cp /lib/x86_64-linux-gnu/libc.so.6 dist/.
apt list --installed > dist/packages.txt

tar cfvz airbag.tar.gz dist
cp airbag.tar.gz ../build/.
