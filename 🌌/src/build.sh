#!/bin/bash

set -ex


mojo build --debug-level 'line-tables' -O0 -o 🌌 ./main.mojo


cp 🌌 ../build/.
mkdir -p ../build/src/
