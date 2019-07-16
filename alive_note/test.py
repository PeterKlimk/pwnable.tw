from pwn import *
context.os     = "linux"
context.arch   = "i386"
context.endian = "little"


bad = """
jmp edx
"""

as_relocate = """
xor dword ptr [edx+0x30], eax
jne $+0x38
"""

print(asm(bad).hex())

brelocate = asm(as_relocate)
print(len(brelocate))
print(brelocate.isalnum())
print([hex(c) for c in brelocate])
print([hex(c) for c in brelocate if not chr(c).isalnum()])