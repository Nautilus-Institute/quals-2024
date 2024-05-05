import os
import sys
import time
import json

HOST = os.environ["HOST"]
PORT = int(os.environ["PORT"])
TICKET = os.environ.get("TICKET")

from pwn import *

context.log_level = "DEBUG"
sock = remote(HOST, PORT)

if TICKET:
    sock.readuntil('Ticket please: ')
    sock.sendline(TICKET.encode("latin-1"))
    
time.sleep(1)

payload = {
	# start:
	# 	    nop                   ; padding so the assembler is happy
	# 	    nop
	# 	    nop
	# 	    nop
	# 	    wait 0 gpio 1         ; Stall until start bit is asserted
	# 	    set x, 15 [4]         ; Preload bit counter, then delay until halfway through
	# 	bitloop:                  ; the first data bit (12 cycles incl wait, set).
	# 	    wait 1 gpio 1
	# 	    nop [3]               ; wait until one cycle before the end. this way we can determine landed or not
	# 	    wait 1 gpio 0 side 1  ; wait on data pin. this either returns immediately or delays up to 6 cycles
	# 	    in pins, 1            ; Shift data bit into ISR
	# 	    jmp x-- bitloop
	# 	done:
	# 	    wait 1 gpio 1         ; wait until start bit is high
	"i": [0x01, 0x20, 0x2f, 0xe4, 0x81, 0x20, 0x42, 0xa3, 0x80, 0x38, 0x01, 0x40, 0x46, 0x00, 0x81, 0x20],

	# in base
	"ib": 1,

	# sideset base
	"sb": 0,

	# sideset en
	"se": 1,

	# sideset count
	"sc": 1,

	# input shiftdir
	"isd": 1,

	# autopush
	"as": 1,

	# push thresh
	"ps": 16,
}

sock.sendline(json.dumps(payload))
sock.recvuntil(b"res: ")
flag = sock.recvline().strip().decode("latin-1")
print(flag)
