#!/bin/bash

# We all make mistakes in life. My only mistake is building C applications
# with bash scripts.

gcc main.c -O0 -g -o challenge -no-pie
strip -s challenge
strip -S challenge
strip challenge
mv challenge sus?

# Copy file so it can be used on the server
# It will end up in /opt/challenge
cp sus? ../build/.

cp sus? ./sus/.

tar cfvz ../build/suscall.tar.gz sus


# You can modify ../.github/workflows/build.yml to change `ARTIFACT_PATH` to point to any single file you want to export from the build (such as a tar.gz).
# Note, all files you put in ../build/. will end up in /opt/. for the artifact.
# So in this case, copying challenge to ../build/ will end up in /opt/challenge,
# so you can change `ARTIFACT_PATH` to /opt/challenge if you want to export the challenge binary, etc
