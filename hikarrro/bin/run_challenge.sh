#!/bin/bash

# close any extra FDs from xinetd
exec 3<&- 4<&-

timeout --foreground -k 1 290 python3 -u ./play_min.py

