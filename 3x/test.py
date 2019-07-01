from pwn import *

context.endian = 'little'
context.arch = 'amd64'

print(shellcraft.amd64.sh())
bat = asm(shellcraft.amd64.sh())
print(len(bat))

p = run_shellcode(bat)
p.interactive()

#rax < 0x3b
#esi <- 0
#rdx <- 0