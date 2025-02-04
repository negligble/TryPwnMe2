from pwn import *

context.binary = binary = ELF('./tryanote')
