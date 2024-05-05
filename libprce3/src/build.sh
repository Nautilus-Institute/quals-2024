#!/bin/bash

# We all make mistakes in life. My only mistake is building C applications
# with bash scripts
set -ex
pushd /deb

ls -la
cp /src/dist/nginx.conf .
tar cfvz /build/pcre3_8.39-16.tar.gz pcre3-8.39 nginx.conf

popd

pushd /deb/pcre3-*

export FAKETIME="2006-04-23 11:13:04"
export BUILD_NUMBER="1"


# Use LD_PRELOAD to load libfaketime
export LD_PRELOAD="/usr/lib/x86_64-linux-gnu/faketime/libfaketime.so.1"

dpkg-buildpackage -b
popd

ls -la /deb

cp /deb/*.deb ../build/.
