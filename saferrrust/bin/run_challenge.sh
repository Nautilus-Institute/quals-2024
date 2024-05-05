#!/bin/bash

# close any extra FDs from xinetd
exec 3<&- 4<&-


(
        cd /opt/writablefolder
        timeout -k 1 --foreground 300 ../saferrrust
)
