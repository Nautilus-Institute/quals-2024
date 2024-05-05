#!/bin/bash
set -e 
SWIFT_BACKTRACE="demangle=no,enable=yes,images=none,interactive=no,registers=none,sanitize=no,swift-backtrace=./swift-backtrace-static,threads=crashed,timeout=0s,output-to=stderr" ./main
