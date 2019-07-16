from pwn import *

#r = process("tcache_tear")
r = process(["gdbserver", "localhost:1234", "./tcache_tear"])
r.interactive()