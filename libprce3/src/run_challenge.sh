#!/bin/sh

export FAKETIME="2006-$(date '+%m-%d %H:%M:%S')"

# Use LD_PRELOAD to load libfaketime
export LD_PRELOAD="/usr/lib/x86_64-linux-gnu/faketime/libfaketime.so.1"

#strace -e unlink,mprotect -s 9999 -f nginx -g 'daemon off;' & # 0</dev/null 1>/dev/null 2>/dev/null &
nohup nginx -g 'daemon off;' 0</dev/null 1>/dev/null 2>/dev/null &

unset LD_PRELOAD

# close any extra FDs from xinetd
exec 3<&- 4<&-

sleep 1

# socat connects to nginx on port 80

exec socat TCP:localhost:8080 STDIO


#exec strace -s 9999 -f nginx -g 'daemon off;'
# only strace the unlink command
#exec strace -e unlink -s 9999 -f nginx -g 'daemon off;'
#exec nginx -g 'daemon off;'
