from pwn import *

r = process("calc")
print(r.read())
while True:
    r.sendline(input())
    print(hex(int((r.read()))))