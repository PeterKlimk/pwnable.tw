from pwn import *

rop = ROP("calc")
help(rop.execve)