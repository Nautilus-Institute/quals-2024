#!/bin/bash
gcc -O3 -fPIE -o walker -msse4.1 main.c -ldl 
strip walker
cp walker ../build/challenge
