from pwn import *
import sys

import time

HOST = os.environ.get("HOST", 'localhost')
PORT = int(os.environ.get("PORT",5555))
TICKET = os.environ.get("TICKET")
p = remote(HOST, PORT)
if TICKET:
    p.readuntil('Ticket please: ')
    p.sendline(TICKET.encode("latin-1"))
context.clear(log_level='warn')

exp = open("exploit2.txt", "rb").read()
print(exp)

v = p.recvline()
print(v)
#import time; time.sleep(200)
p.send(b"\n".join(exp.split(b"\n")[:40])+b"\n")
p.send(b"\n".join(exp.split(b"\n")[40:])+b"\n")

while True:
    v = p.recvline()
    print(v)
    if b"flag" in v:
        break

flag = v.split(b" b'")[1].split(b"}")[0] + b"}"
print("flag len", len(flag))
assert b"flag{" in flag
assert b"}" in flag
print("FLAG:", flag)


