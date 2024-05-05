#!/bin/bash

set -ex

ls -la

mkdir -p ../build/src
cp -r *.py ../build/src/.

mkdir -p 🔭/🗄️
cp -r *.py *.mojo 🔭/🗄️/.

#rm 🔭/src/debug_util.mojo

for file in 🔭/🗄️/*.mojo; do mv "$file" "${file%.mojo}.✨"; done

cp 🌌 🔭/.
cp -r /dist/* 🔭/.


tar -czvf 🌌.tar.gz 🔭
cp 🌌.tar.gz ../build/.
