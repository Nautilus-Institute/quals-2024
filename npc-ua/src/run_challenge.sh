#!/bin/sh

# close any extra FDs from xinetd
exec 3<&- 4<&-

openssl ecparam -out /opt/private.ec.pem -name secp256k1 -genkey -noout && openssl ec -in /opt/private.ec.pem -pubout -out /opt/public.ec.pem && chmod o+r /opt/*.ec.pem 2>/dev/null >/dev/null

exec dotnet /opt/npcua.nautilus.dll
