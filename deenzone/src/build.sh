#!/bin/bash

# We all make mistakes in life. My only mistake is building C applications
# with bash scripts.
make all
# strip the challenge binary
strip deenzone

# Copy file so it can be used on the server
# It will end up in /opt/challenge
cp deenzone ../build/.
#cp a.out ../build/.
cp config.json ../build/.

# make the dist dir for player release
mkdir -p dist
# copy in the challenge binary
cp deenzone ./dist/
# copy the helper script to pull libs into dist
cp libs.sh ./dist/
# run our config sanitizer which will place the sanitized config into dist
python3 config_sanitizer.py

# tar it up
tar cfvz deenzone.tar.gz dist
# put it in the build dir
cp deenzone.tar.gz ../build/.
