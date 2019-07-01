from pwn import *

bin  = elf.ELF("/lib32/libc.so.6")
print(bin.symbols)