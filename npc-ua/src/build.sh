#!/bin/bash

set -e

# We all make mistakes in life. My only mistake is building C applications
# with bash scripts.

dotnet build -c Release
#dotnet build -c Debug

# Copy file so it can be used on the server
# It will end up in /opt/challenge
#cp ./bin/Release/net6.0/{*.dll,src,*.json} ../build/.
#cp ./bin/Debug/net6.0/{*.dll,npc_ua,*.json} ../build/.
cp ./bin/Release/net6.0/{*.dll,*.json} ../build/.

mkdir -p dist/server/nugetlibs/

cp ./bin/Release/net6.0/*.dll dist/server/nugetlibs/
mv ./dist/server/nugetlibs/*.nautilus.dll ./dist/server/.
cp StatusCode.csv ./bin/Release/net6.0/*.json dist/server

tar cfvz ic_server.tar.gz dist
cp ic_server.tar.gz StatusCode.csv private.ec.pem public.ec.pem ../build/.
