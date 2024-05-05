#!/bin/bash
set -x
set -e

cd /deb/pcre3-*
cat /src/changelog.txt debian/changelog > /tmp/v
mv /tmp/v debian/changelog
git apply /src/patch.patch